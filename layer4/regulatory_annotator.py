"""
Layer 4 — Regulatory Scope Annotator.

Derives the regulatory scope for each Service node without requiring manual YAML.
Three evidence sources are combined, highest-confidence wins:

  1. Explicit annotation — a comment in the codebase:
       # lsig:regulatory=PCI,GDPR  or  // lsig:regulatory=HIPAA
  2. PII field evidence — if the service exposes fields of type CREDIT_CARD → PCI,
     HEALTH_DATA → HIPAA, any PII field accessed from the EU → GDPR, etc.
  3. Service name pattern matching — "payment", "billing" → PCI; "health", "patient" → HIPAA.

Regulatory scopes: PCI | HIPAA | GDPR | SOC2 | NONE

The derived scope is stored as regulatory_scope[] on the Service node.
Endpoints with PII fields are annotated with a pci_scope / hipaa_scope flag.

Usage:
    python -m layer4.regulatory_annotator --service myapp --repo /path/to/repo
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path

from layer1.neo4j_client import run_query, upsert_node

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── Regulatory scope constants ───────────────────────────────────────────────

SCOPES = frozenset({"PCI", "HIPAA", "GDPR", "SOC2", "NONE"})

# ─── Evidence source 1: explicit inline annotations ──────────────────────────

_ANNOTATION_PATTERN = re.compile(
    r"lsig:regulatory\s*=\s*([\w,\s]+)",
    re.IGNORECASE,
)


def _extract_annotations_from_source(source: str) -> list[str]:
    """
    Scan source code for inline regulatory annotations.
    e.g.  # lsig:regulatory=PCI,GDPR
    Returns list of scope strings.
    """
    scopes: list[str] = []
    for match in _ANNOTATION_PATTERN.finditer(source):
        raw = match.group(1)
        for scope in re.split(r"[,\s]+", raw):
            scope = scope.strip().upper()
            if scope in SCOPES:
                scopes.append(scope)
    return scopes


def scan_repo_for_annotations(repo_dir: Path) -> list[str]:
    """Return all regulatory scopes found in inline annotations across the repo."""
    found: set[str] = set()
    skip_dirs = {".git", "node_modules", "__pycache__", "vendor", ".venv", "dist", "build"}
    extensions = {".py", ".js", ".ts", ".go", ".java", ".rb", ".yaml", ".yml", ".toml"}

    for path in repo_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix not in extensions:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            found.update(_extract_annotations_from_source(source))
        except OSError:
            continue

    return list(found)


# ─── Evidence source 2: PII field types ───────────────────────────────────────

# Maps PII type → implied regulatory scope
_PII_TO_SCOPE: dict[str, list[str]] = {
    "CREDIT_CARD": ["PCI"],
    "BANK_ACCOUNT": ["PCI"],
    "SSN":          ["HIPAA", "GDPR"],
    "HEALTH_DATA":  ["HIPAA"],
    "MEDICAL_ID":   ["HIPAA"],
    "EMAIL":        ["GDPR"],
    "PHONE":        ["GDPR"],
    "PERSON_NAME":  ["GDPR"],
    "LOCATION":     ["GDPR"],
    "DATE_OF_BIRTH":["GDPR", "HIPAA"],
    "GOVERNMENT_ID":["GDPR"],
    "SENSITIVE_DEMOGRAPHIC": ["GDPR"],
    "IP_ADDRESS":   ["GDPR"],
    "CREDENTIAL":   ["SOC2"],
    "FINANCIAL":    ["PCI", "SOC2"],
}


def derive_scope_from_pii_fields(service: str) -> list[str]:
    """
    Query the DataField nodes for this service and infer regulatory scope
    from the PII types present.
    """
    rows = run_query(
        """
        MATCH (d:DataField {service: $svc, pii_likely: true})
        WHERE d.deprecated_at IS NULL AND d.pii_type IS NOT NULL
        RETURN DISTINCT d.pii_type AS pii_type
        """,
        {"svc": service},
    )
    scopes: set[str] = set()
    for row in rows:
        pii_type = row.get("pii_type", "")
        scopes.update(_PII_TO_SCOPE.get(pii_type, []))
    return list(scopes)


# ─── Evidence source 3: service name patterns ─────────────────────────────────

_NAME_TO_SCOPE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(pay|payment|billing|invoice|checkout|card|stripe|braintree|commerce)\b", re.I), "PCI"),
    (re.compile(r"\b(health|patient|clinical|ehr|emr|medical|pharmacy|prescription|hipaa)\b", re.I), "HIPAA"),
    (re.compile(r"\b(user|account|profile|identity|auth|login|register|gdpr|consent)\b", re.I), "GDPR"),
    (re.compile(r"\b(audit|compliance|security|soc2|access|permission|log|report)\b", re.I), "SOC2"),
]


def derive_scope_from_service_name(service_name: str) -> list[str]:
    """Infer regulatory scope from the service's name."""
    scopes: set[str] = set()
    for pattern, scope in _NAME_TO_SCOPE:
        if pattern.search(service_name):
            scopes.add(scope)
    return list(scopes)


# ─── Scope combiner ───────────────────────────────────────────────────────────

@dataclass
class ScopeEvidence:
    annotation_scopes: list[str] = field(default_factory=list)
    pii_scopes: list[str] = field(default_factory=list)
    name_scopes: list[str] = field(default_factory=list)

    @property
    def combined(self) -> list[str]:
        """Union of all evidence sources, deduped, sorted."""
        all_scopes = set(self.annotation_scopes) | set(self.pii_scopes) | set(self.name_scopes)
        result = sorted(all_scopes & SCOPES)
        return result if result else ["NONE"]

    @property
    def confidence(self) -> str:
        """HIGH if explicit annotation, MEDIUM if PII evidence, LOW if name-only."""
        if self.annotation_scopes:
            return "HIGH"
        if self.pii_scopes:
            return "MEDIUM"
        return "LOW"


# ─── Neo4j write ─────────────────────────────────────────────────────────────

def _write_regulatory_scope(
    service: str, scopes: list[str], confidence: str
) -> None:
    run_query(
        """
        MATCH (s:Service {id: $svc})
        SET s.regulatory_scope      = $scopes,
            s.scope_confidence      = $confidence,
            s.scope_derived_at      = datetime()
        """,
        {"svc": service, "scopes": scopes, "confidence": confidence},
    )


def _annotate_pci_endpoints(service: str) -> int:
    """Mark endpoints that handle credit card fields as pci_scope=true."""
    result = run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(f:Function)
        MATCH (f)-[:CALLS*0..8]->(g:Function)-[:READS|WRITES]->(d:DataField)
        WHERE d.pii_type IN ['CREDIT_CARD', 'BANK_ACCOUNT', 'FINANCIAL']
          AND ep.deprecated_at IS NULL
        SET ep.pci_scope = true
        RETURN count(DISTINCT ep) AS cnt
        """,
        {"svc": service},
    )
    count = result[0]["cnt"] if result else 0
    if count:
        logger.info("Marked %d endpoints as pci_scope for service=%s", count, service)
    return count


def _annotate_hipaa_endpoints(service: str) -> int:
    result = run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(f:Function)
        MATCH (f)-[:CALLS*0..8]->(g:Function)-[:READS|WRITES]->(d:DataField)
        WHERE d.pii_type IN ['HEALTH_DATA', 'MEDICAL_ID', 'SSN']
          AND ep.deprecated_at IS NULL
        SET ep.hipaa_scope = true
        RETURN count(DISTINCT ep) AS cnt
        """,
        {"svc": service},
    )
    count = result[0]["cnt"] if result else 0
    if count:
        logger.info("Marked %d endpoints as hipaa_scope for service=%s", count, service)
    return count


# ─── Main entry point ─────────────────────────────────────────────────────────

def annotate(service: str, repo_dir: str | Path | None = None) -> dict:
    """
    Derive and persist regulatory scope for a service.

    Args:
        service:   Service node ID.
        repo_dir:  Repo path for explicit annotation scanning (optional).

    Returns:
        Summary dict.
    """
    evidence = ScopeEvidence()

    # Source 1: explicit annotations
    if repo_dir:
        evidence.annotation_scopes = scan_repo_for_annotations(Path(repo_dir))
        if evidence.annotation_scopes:
            logger.info(
                "Found explicit regulatory annotations for %s: %s",
                service, evidence.annotation_scopes,
            )

    # Source 2: PII field evidence
    evidence.pii_scopes = derive_scope_from_pii_fields(service)

    # Source 3: service name
    evidence.name_scopes = derive_scope_from_service_name(service)

    final_scopes = evidence.combined
    confidence = evidence.confidence

    _write_regulatory_scope(service, final_scopes, confidence)
    logger.info(
        "Regulatory scope for service=%s: %s (confidence=%s)",
        service, final_scopes, confidence,
    )

    pci_endpoints = _annotate_pci_endpoints(service)
    hipaa_endpoints = _annotate_hipaa_endpoints(service)

    return {
        "status": "ok",
        "service": service,
        "regulatory_scope": final_scopes,
        "confidence": confidence,
        "evidence": {
            "annotation": evidence.annotation_scopes,
            "pii_fields": evidence.pii_scopes,
            "name_pattern": evidence.name_scopes,
        },
        "pci_endpoints_marked": pci_endpoints,
        "hipaa_endpoints_marked": hipaa_endpoints,
    }


def annotate_all_services(repo_dirs: dict[str, str] | None = None) -> list[dict]:
    """Annotate regulatory scope for all Service nodes."""
    services = run_query(
        "MATCH (s:Service) WHERE s.deprecated_at IS NULL RETURN s.id AS id"
    )
    results = []
    for svc in services:
        svc_id = svc["id"]
        repo = (repo_dirs or {}).get(svc_id)
        results.append(annotate(svc_id, repo))
    return results


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(description="LSIG Layer 4 — Regulatory Annotator")
    parser.add_argument("--service", help="Service to annotate")
    parser.add_argument("--repo", help="Repo path for annotation scanning")
    parser.add_argument("--all", action="store_true", help="Annotate all services")
    args = parser.parse_args()
    if args.all:
        print(json.dumps(annotate_all_services(), indent=2))
    elif args.service:
        print(json.dumps(annotate(args.service, args.repo), indent=2))
    else:
        parser.error("Provide --service or --all")
