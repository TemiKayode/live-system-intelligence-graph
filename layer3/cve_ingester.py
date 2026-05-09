"""
Layer 3 — CVE Ingestion Pipeline.

Polls OSV and GHSA APIs every 6 hours. For each advisory:
  1. Creates/updates a Vulnerability node in Neo4j.
  2. Links Dependency nodes that match the affected package/version range.
  3. Enriches each with EPSS score from FIRST.org.
  4. Marks confirmed-exploited vulnerabilities from the CISA KEV feed.

Run standalone (polls once then exits):
    python -m layer3.cve_ingester --service myapp

Or as a daemon (polls every 6 hours):
    python -m layer3.cve_ingester --daemon
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

import urllib.request
import urllib.error

from layer1.neo4j_client import run_query, upsert_node, upsert_relationship
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── API URLs ─────────────────────────────────────────────────────────────────

OSV_QUERY_URL    = "https://api.osv.dev/v1/query"
OSV_VULN_URL     = "https://api.osv.dev/v1/vulns/{osv_id}"
GHSA_API_URL     = "https://api.github.com/graphql"
EPSS_API_URL     = "https://api.first.org/data/v1/epss?cve={cve_id}"
KEV_FEED_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityRecord:
    osv_id: str
    cve_id: str | None
    affected_package: str
    affected_ecosystem: str
    affected_versions: list[str]           # exact versions
    affected_version_ranges: list[dict]    # [{introduced, fixed}]
    vulnerable_functions: list[str]        # symbol names, if OSV provides them
    severity: str                          # CRITICAL|HIGH|MEDIUM|LOW
    epss_score: float
    in_kev: bool
    published_at: datetime
    aliases: list[str]


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict | None = None) -> dict | list:
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("User-Agent", "LSIG/1.0 (security posture engine)")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _http_post(url: str, body: dict, headers: dict | None = None) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "LSIG/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# ─── EPSS enrichment ──────────────────────────────────────────────────────────

# Cache: cve_id → epss_score. Refreshed once per run.
_epss_cache: dict[str, float] = {}


def fetch_epss(cve_id: str) -> float:
    """Return the EPSS probability score [0.0, 1.0] for a CVE, or 0.0 if unknown."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    if cve_id in _epss_cache:
        return _epss_cache[cve_id]

    def _fetch():
        data = _http_get(EPSS_API_URL.format(cve_id=cve_id))
        items = data.get("data", [])  # type: ignore[union-attr]
        if items:
            score = float(items[0].get("epss", 0.0))
            _epss_cache[cve_id] = score
            return score
        return 0.0

    try:
        return with_retry(_fetch, label=f"epss:{cve_id}", max_attempts=3,
                          exceptions=(urllib.error.URLError, Exception))
    except Exception as e:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, e)
        return 0.0


# ─── CISA KEV feed ────────────────────────────────────────────────────────────

_kev_set: set[str] = set()
_kev_loaded_at: datetime | None = None


def _load_kev() -> set[str]:
    global _kev_set, _kev_loaded_at
    now = datetime.now(timezone.utc)

    # Refresh once per 24 hours
    if _kev_loaded_at and (now - _kev_loaded_at).total_seconds() < 86400:
        return _kev_set

    def _fetch():
        data = _http_get(KEV_FEED_URL)
        vulns = data.get("vulnerabilities", [])  # type: ignore[union-attr]
        return {v["cveID"] for v in vulns if "cveID" in v}

    try:
        _kev_set = with_retry(_fetch, label="kev:feed", max_attempts=3,
                              exceptions=(urllib.error.URLError, Exception))
        _kev_loaded_at = now
        logger.info("KEV feed loaded: %d confirmed-exploited CVEs", len(_kev_set))
    except Exception as e:
        logger.warning("KEV feed load failed: %s", e)

    return _kev_set


def is_in_kev(cve_id: str | None) -> bool:
    if not cve_id:
        return False
    return cve_id in _load_kev()


# ─── Severity mapping ─────────────────────────────────────────────────────────

def _severity_from_osv(osv_record: dict) -> str:
    """
    Derive a severity string from an OSV record.
    Priority: database_specific.severity → severity[].score CVSS → aliases heuristic.
    """
    # OSV severity array: [{type: "CVSS_V3", score: "CVSS:3.1/AV:N/..."}]
    for sev in osv_record.get("severity", []):
        score_str = sev.get("score", "")
        if "CVSS:3" in score_str or "CVSS:4" in score_str:
            # Extract base score from CVSS vector
            base = _cvss_base_score(score_str)
            return _cvss_to_severity(base)

    # Fallback: database_specific.severity (NVD style)
    db = osv_record.get("database_specific", {})
    sev = db.get("severity", "")
    if sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev.upper()

    # Fallback: EPSS > 0.7 → HIGH, else MEDIUM
    cve_id = _first_cve(osv_record)
    if cve_id:
        epss = fetch_epss(cve_id)
        if epss >= 0.7:
            return "HIGH"

    return "MEDIUM"


def _cvss_base_score(vector: str) -> float:
    """Very simplified CVSS base score extraction from vector string."""
    # Real implementations use cvss library; we parse the first numeric group.
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → base=9.8
    # The base score isn't in the vector; use impact heuristic.
    high_impact = vector.count(":H")
    critical_impact = vector.count(":C")
    if high_impact >= 3 or critical_impact >= 1:
        return 9.0
    if high_impact >= 2:
        return 7.5
    if high_impact >= 1:
        return 5.5
    return 3.5


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _first_cve(osv_record: dict) -> str | None:
    for alias in osv_record.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return None


# ─── Version range matching ───────────────────────────────────────────────────

def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Convert "1.2.3" → (1, 2, 3). Non-numeric parts become 0."""
    parts = re.split(r"[.\-_]", v)
    result = []
    for p in parts[:4]:
        try:
            result.append(int(re.sub(r"[^0-9]", "", p) or "0"))
        except ValueError:
            result.append(0)
    return tuple(result)


def version_in_range(version: str, ranges: list[dict]) -> bool:
    """
    Return True if `version` falls within any of the OSV affected version ranges.
    ranges: [{"introduced": "0", "fixed": "1.2.3"}, ...]
    """
    v = _parse_version_tuple(version)
    for r in ranges:
        introduced = _parse_version_tuple(r.get("introduced", "0"))
        fixed_str = r.get("fixed", "")
        last_affected_str = r.get("last_affected", "")

        if fixed_str:
            fixed = _parse_version_tuple(fixed_str)
            if introduced <= v < fixed:
                return True
        elif last_affected_str:
            last = _parse_version_tuple(last_affected_str)
            if introduced <= v <= last:
                return True
        else:
            if v >= introduced:
                return True
    return False


# ─── OSV API ─────────────────────────────────────────────────────────────────

def query_osv_for_package(name: str, ecosystem: str, version: str) -> list[dict]:
    """Query the OSV API for vulnerabilities affecting a specific package@version."""
    # Map LSIG ecosystem names to OSV ecosystem names
    osv_ecosystem_map = {
        "pypi": "PyPI",
        "npm": "npm",
        "go": "Go",
        "maven": "Maven",
        "gem": "RubyGems",
        "cargo": "crates.io",
        "nuget": "NuGet",
        "deb": "Debian",
        "apk": "Alpine",
    }
    osv_ecosystem = osv_ecosystem_map.get(ecosystem, ecosystem)

    body = {
        "version": version,
        "package": {"name": name, "ecosystem": osv_ecosystem},
    }

    def _fetch():
        data = _http_post(OSV_QUERY_URL, body)
        return data.get("vulns", [])

    try:
        return with_retry(_fetch, label=f"osv:{ecosystem}:{name}",
                          max_attempts=3, exceptions=(Exception,))
    except Exception as e:
        logger.debug("OSV query failed for %s@%s: %s", name, version, e)
        return []


def fetch_osv_detail(osv_id: str) -> dict:
    """Fetch full OSV advisory detail."""
    def _fetch():
        return _http_get(OSV_VULN_URL.format(osv_id=osv_id))

    return with_retry(_fetch, label=f"osv:detail:{osv_id}",
                      max_attempts=3, exceptions=(Exception,))


# ─── GHSA API (GitHub token optional — unauthenticated has low rate limits) ───

_GHSA_QUERY = """
query($after: String) {
  securityAdvisories(first: 100, after: $after, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      severity
      publishedAt
      identifiers { type value }
      vulnerabilities(first: 10) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""


def fetch_ghsa_advisories(max_pages: int = 5) -> list[dict]:
    """Fetch recent GHSA advisories via the GitHub GraphQL API."""
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Authorization": f"bearer {token}"} if token else {}

    results = []
    cursor = None
    for _ in range(max_pages):
        body = {"query": _GHSA_QUERY, "variables": {"after": cursor}}
        try:
            data = with_retry(
                lambda: _http_post(GHSA_API_URL, body, headers),
                label="ghsa:advisories", max_attempts=3, exceptions=(Exception,),
            )
        except Exception as e:
            logger.warning("GHSA fetch failed: %s", e)
            break

        advisories = data.get("data", {}).get("securityAdvisories", {})
        results.extend(advisories.get("nodes", []))
        page_info = advisories.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")

    return results


# ─── Vulnerability node builder ───────────────────────────────────────────────

def _build_vuln_record(osv_id: str, detail: dict) -> VulnerabilityRecord:
    cve_id = _first_cve(detail)
    affected = detail.get("affected", [])

    # Collect affected package info from first affected entry
    pkg_name = ""
    pkg_ecosystem = ""
    exact_versions: list[str] = []
    version_ranges: list[dict] = []
    vulnerable_functions: list[str] = []

    for aff in affected:
        pkg = aff.get("package", {})
        if not pkg_name:
            pkg_name = pkg.get("name", "")
            pkg_ecosystem = pkg.get("ecosystem", "").lower()

        for ver in aff.get("versions", []):
            exact_versions.append(ver)

        for rng in aff.get("ranges", []):
            if rng.get("type") in ("SEMVER", "ECOSYSTEM", "GIT"):
                # OSV events list introduced/fixed alternately; pair them up.
                introduced = None
                for ev in rng.get("events", []):
                    if "introduced" in ev:
                        introduced = ev["introduced"]
                    elif "fixed" in ev and introduced is not None:
                        version_ranges.append({"introduced": introduced, "fixed": ev["fixed"]})
                        introduced = None
                    elif "last_affected" in ev and introduced is not None:
                        version_ranges.append({"introduced": introduced, "last_affected": ev["last_affected"]})
                        introduced = None
                # Open-ended range (introduced with no fixed yet)
                if introduced is not None:
                    version_ranges.append({"introduced": introduced, "fixed": None})

        # OSV ecosystem_specific may list vulnerable function names
        eco_specific = aff.get("ecosystem_specific", {})
        vulnerable_functions.extend(eco_specific.get("functions", []))

    severity = _severity_from_osv(detail)
    epss = fetch_epss(cve_id) if cve_id else 0.0
    in_kev = is_in_kev(cve_id)

    published_str = detail.get("published", "1970-01-01T00:00:00Z")
    try:
        published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
    except ValueError:
        published_at = datetime.now(timezone.utc)

    return VulnerabilityRecord(
        osv_id=osv_id,
        cve_id=cve_id,
        affected_package=pkg_name,
        affected_ecosystem=pkg_ecosystem,
        affected_versions=exact_versions,
        affected_version_ranges=version_ranges,
        vulnerable_functions=vulnerable_functions,
        severity=severity,
        epss_score=epss,
        in_kev=in_kev,
        published_at=published_at,
        aliases=detail.get("aliases", []),
    )


# ─── Neo4j upsert ─────────────────────────────────────────────────────────────

def _upsert_vulnerability(rec: VulnerabilityRecord) -> None:
    vuln_id = rec.cve_id or rec.osv_id
    upsert_node(
        "Vulnerability",
        id_props={"id": vuln_id},
        extra_props={
            "cve_id": rec.cve_id,
            "osv_id": rec.osv_id,
            "affected_package": rec.affected_package,
            "affected_versions": rec.affected_versions,
            "vulnerable_functions": rec.vulnerable_functions,
            "severity": rec.severity,
            "epss_score": rec.epss_score,
            "in_kev": rec.in_kev,
            "published_at": rec.published_at.isoformat(),
            "aliases": rec.aliases,
        },
    )


def _link_dependency_to_vuln(
    dep_id: str, vuln_id: str, severity: str, epss_score: float, in_kev: bool
) -> None:
    """Create (Dependency)-[:HAS_VULN]->(Vulnerability) with reachability=UNKNOWN."""
    run_query(
        """
        MATCH (d:Dependency {id: $dep_id})
        MATCH (v:Vulnerability {id: $vuln_id})
        MERGE (d)-[r:HAS_VULN]->(v)
        ON CREATE SET
            r.severity     = $severity,
            r.epss_score   = $epss,
            r.in_kev       = $in_kev,
            r.reachability = 'UNKNOWN',
            r.linked_at    = datetime()
        ON MATCH SET
            r.severity     = $severity,
            r.epss_score   = $epss,
            r.in_kev       = $in_kev
        """,
        {
            "dep_id": dep_id, "vuln_id": vuln_id,
            "severity": severity, "epss": epss_score, "in_kev": in_kev,
        },
    )


def _find_matching_dependencies(rec: VulnerabilityRecord) -> list[dict]:
    """
    Find all Dependency nodes that match this vulnerability's affected package.
    Matches by name + ecosystem, then filters by version range.
    """
    rows = run_query(
        """
        MATCH (d:Dependency)
        WHERE d.name = $name
          AND d.ecosystem = $ecosystem
          AND d.deprecated_at IS NULL
        RETURN d.id AS id, d.version AS version, d.service AS service
        """,
        {"name": rec.affected_package, "ecosystem": rec.affected_ecosystem},
    )

    matching = []
    for row in rows:
        version = row["version"] or ""
        in_exact = version in rec.affected_versions
        in_range = version_in_range(version, rec.affected_version_ranges)
        if in_exact or in_range:
            matching.append(row)

    return matching


# ─── Main ingestion loop ──────────────────────────────────────────────────────

def ingest_for_service(service: str) -> dict:
    """
    Run CVE ingestion for all dependencies of a specific service.
    Fetches OSV advisories for each dependency and links them.
    """
    # Get all dependencies for this service
    deps = run_query(
        """
        MATCH (d:Dependency {service: $svc})
        WHERE d.deprecated_at IS NULL
        RETURN d.id AS id, d.name AS name, d.version AS version, d.ecosystem AS ecosystem
        """,
        {"svc": service},
    )

    if not deps:
        logger.warning("No Dependency nodes found for service=%s", service)
        return {"status": "no_dependencies", "service": service}

    vulns_found = 0
    links_created = 0
    _load_kev()  # pre-load KEV feed once

    for dep in deps:
        osv_vulns = query_osv_for_package(dep["name"], dep["ecosystem"], dep["version"])
        for osv_summary in osv_vulns:
            osv_id = osv_summary.get("id", "")
            if not osv_id:
                continue
            try:
                detail = fetch_osv_detail(osv_id)
                rec = _build_vuln_record(osv_id, detail)
                _upsert_vulnerability(rec)

                vuln_id = rec.cve_id or rec.osv_id
                _link_dependency_to_vuln(
                    dep["id"], vuln_id, rec.severity, rec.epss_score, rec.in_kev
                )
                vulns_found += 1
                links_created += 1
            except Exception as e:
                logger.warning("Failed to process %s: %s", osv_id, e)

    summary = {
        "status": "ok",
        "service": service,
        "dependencies_scanned": len(deps),
        "vulnerabilities_found": vulns_found,
        "links_created": links_created,
    }
    logger.info("CVE ingest complete: %s", summary)
    return summary


def ingest_all_services() -> list[dict]:
    """Run CVE ingestion for every service in the graph."""
    services = run_query(
        "MATCH (s:Service) WHERE s.deprecated_at IS NULL RETURN s.id AS id"
    )
    results = []
    for svc in services:
        results.append(ingest_for_service(svc["id"]))
    return results


def run_daemon(interval_hours: int = 6) -> None:
    """Poll for new CVEs every interval_hours. Runs until interrupted."""
    logger.info("CVE daemon starting — interval=%dh", interval_hours)
    while True:
        try:
            ingest_all_services()
        except Exception as e:
            logger.error("CVE ingest cycle failed: %s", e)
        logger.info("Next CVE poll in %d hours", interval_hours)
        time.sleep(interval_hours * 3600)


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSIG Layer 3 — CVE Ingester")
    parser.add_argument("--service", help="Run for a specific service only")
    parser.add_argument("--daemon", action="store_true", help="Run as a polling daemon")
    parser.add_argument("--interval", type=int, default=6, help="Poll interval (hours)")
    args = parser.parse_args()

    if args.daemon:
        run_daemon(args.interval)
    elif args.service:
        result = ingest_for_service(args.service)
        print(json.dumps(result, indent=2))
    else:
        results = ingest_all_services()
        print(json.dumps(results, indent=2))
