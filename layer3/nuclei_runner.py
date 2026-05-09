"""
Layer 3 — Nuclei Attack Surface Runner.

Runs Nuclei against each service's external URL to enumerate reachable endpoints
and stores them as ExternalEndpoint nodes linked to APIEndpoint nodes via
path-matching.

Schedule: daily (called by Temporal scheduler in Layer 6 or standalone cron).

Usage:
    python -m layer3.nuclei_runner --service myapp --url https://api.myapp.com
    python -m layer3.nuclei_runner --all          # runs all services with a url
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from layer1.neo4j_client import run_query, upsert_node
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── Nuclei availability check ────────────────────────────────────────────────

def _nuclei_available() -> bool:
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# ─── Nuclei result schema ──────────────────────────────────────────────────────

# Example Nuclei JSONL output line:
# {"template-id":"...", "matched-at":"https://api.example.com/api/v1/users",
#  "severity":"info", "host":"api.example.com", "timestamp":"..."}

def _parse_nuclei_output(output_path: Path) -> list[dict]:
    results = []
    for line in output_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def _extract_paths(nuclei_results: list[dict]) -> list[str]:
    """Extract URL paths from Nuclei results, normalised to /path/segments."""
    paths = set()
    for item in nuclei_results:
        matched_at = item.get("matched-at", "")
        if not matched_at:
            continue
        try:
            parsed = urlparse(matched_at)
            path = parsed.path.rstrip("/") or "/"
            paths.add(path)
        except Exception:
            continue
    return sorted(paths)


# ─── Nuclei runner ────────────────────────────────────────────────────────────

# Templates used for endpoint discovery (not vulnerability exploitation).
# These are informational probes only — no destructive or auth-bypass templates.
_SAFE_TEMPLATES = [
    "http/technologies",          # technology fingerprinting
    "http/exposures",             # exposed files / endpoints
    "http/miscellaneous",         # robots.txt, sitemap, swagger
    "http/misconfiguration",      # directory listing, debug endpoints
]


def run_nuclei(target_url: str, output_path: Path) -> list[dict]:
    """
    Run Nuclei against target_url with discovery-only templates.
    Returns list of finding dicts.
    """
    if not _nuclei_available():
        logger.warning("nuclei not found in PATH — skipping attack surface scan")
        return []

    cmd = [
        "nuclei",
        "--target", target_url,
        "--output", str(output_path),
        "--jsonl",
        "--silent",
        "--no-interactsh",       # disable out-of-band callbacks
        "--rate-limit", "50",    # be a good citizen
        "--timeout", "10",
        "--retries", "1",
    ]
    # Add safe template tags
    for template in _SAFE_TEMPLATES:
        cmd += ["--tags", template]

    logger.info("Running Nuclei: %s", target_url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):  # nuclei returns 1 when findings exist
            logger.warning("Nuclei exited with code %d: %s",
                           result.returncode, result.stderr[:200])
    except subprocess.TimeoutExpired:
        logger.warning("Nuclei timed out for %s", target_url)

    if output_path.exists():
        return _parse_nuclei_output(output_path)
    return []


# ─── Path matching: ExternalEndpoint → APIEndpoint ───────────────────────────

def _path_to_pattern(path: str) -> str:
    """
    Convert a concrete URL path to a pattern for matching against APIEndpoint paths.
    e.g. "/api/v1/users/123" → "/api/v1/users/{...}"
         "/api/v1/users" → "/api/v1/users"
    """
    # Replace numeric segments with wildcards
    pattern = re.sub(r"/\d+", "/{id}", path)
    # Replace UUID segments
    pattern = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{uuid}", pattern, flags=re.IGNORECASE,
    )
    return pattern


def _find_matching_api_endpoints(service: str, url_path: str) -> list[str]:
    """
    Find APIEndpoint node IDs in the graph that match the given URL path.
    Matches exact paths, parameterised paths, and prefix matches.
    """
    pattern = _path_to_pattern(url_path)
    rows = run_query(
        """
        MATCH (e:APIEndpoint {service: $svc})
        WHERE e.deprecated_at IS NULL
          AND (
            e.path = $exact
            OR e.path = $pattern
            OR $exact STARTS WITH e.path
          )
        RETURN e.id AS id, e.path AS path
        """,
        {"svc": service, "exact": url_path, "pattern": pattern},
    )
    return [r["id"] for r in rows]


# ─── Neo4j upsert ─────────────────────────────────────────────────────────────

def _upsert_external_endpoint(
    service: str, url: str, path: str, template_id: str, severity: str
) -> str:
    """Upsert an ExternalEndpoint node. Returns the node ID."""
    ext_id = hashlib.sha256(f"{service}:{url}".encode()).hexdigest()[:16]
    upsert_node(
        "ExternalEndpoint",
        id_props={"id": ext_id},
        extra_props={
            "url": url,
            "path": path,
            "service": service,
            "template_id": template_id,
            "severity": severity,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return ext_id


def _link_external_to_api(ext_id: str, api_endpoint_id: str) -> None:
    run_query(
        """
        MATCH (ext:ExternalEndpoint {id: $ext_id})
        MATCH (ep:APIEndpoint {id: $ep_id})
        MERGE (ext)-[:MAPS_TO]->(ep)
        """,
        {"ext_id": ext_id, "ep_id": api_endpoint_id},
    )


# ─── Main scan entry point ────────────────────────────────────────────────────

def scan(service: str, target_url: str) -> dict:
    """
    Run a Nuclei scan against target_url, upsert ExternalEndpoint nodes,
    and link them to APIEndpoint nodes in the code graph.

    Returns a summary dict.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "nuclei.jsonl"
        findings = with_retry(
            lambda: run_nuclei(target_url, output_path),
            label=f"nuclei:{service}",
            max_attempts=2,
        )

    paths_discovered = _extract_paths(findings)
    logger.info(
        "Nuclei scan complete: service=%s url=%s findings=%d paths=%d",
        service, target_url, len(findings), len(paths_discovered),
    )

    endpoints_created = 0
    links_created = 0
    finding_by_path = {
        urlparse(f.get("matched-at", "")).path: f
        for f in findings
        if f.get("matched-at")
    }

    for path in paths_discovered:
        finding = finding_by_path.get(path, {})
        full_url = target_url.rstrip("/") + path
        ext_id = _upsert_external_endpoint(
            service=service,
            url=full_url,
            path=path,
            template_id=finding.get("template-id", ""),
            severity=finding.get("severity", "info"),
        )
        endpoints_created += 1

        # Link to matching APIEndpoint nodes
        api_ids = _find_matching_api_endpoints(service, path)
        for api_id in api_ids:
            _link_external_to_api(ext_id, api_id)
            links_created += 1

    return {
        "status": "ok",
        "service": service,
        "target_url": target_url,
        "nuclei_findings": len(findings),
        "paths_discovered": len(paths_discovered),
        "external_endpoints_created": endpoints_created,
        "api_endpoint_links": links_created,
    }


def scan_all_services() -> list[dict]:
    """Scan all services that have a configured external URL."""
    services = run_query(
        """
        MATCH (s:Service)
        WHERE s.deprecated_at IS NULL AND s.external_url IS NOT NULL
        RETURN s.id AS id, s.external_url AS url
        """
    )
    return [scan(svc["id"], svc["url"]) for svc in services]


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSIG Layer 3 — Nuclei Attack Surface Runner")
    parser.add_argument("--service", help="Service name")
    parser.add_argument("--url", help="Target URL to scan")
    parser.add_argument("--all", action="store_true",
                        help="Scan all services with a configured external_url")
    args = parser.parse_args()

    if args.all:
        results = scan_all_services()
        print(json.dumps(results, indent=2))
    elif args.service and args.url:
        result = scan(args.service, args.url)
        print(json.dumps(result, indent=2))
    else:
        parser.error("Provide --service + --url, or --all")
