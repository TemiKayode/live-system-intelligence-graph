"""
Layer 4 — PII Detector.

Uses Microsoft Presidio to identify PII in:
  1. DataField node names (field names like "email", "ssn", "credit_card_number").
  2. Source code context surrounding field definitions (variable declarations,
     ORM model fields, schema definitions, serializer fields).

Marks DataField nodes with:
  pii_likely: true
  pii_type:   "EMAIL" | "PHONE_NUMBER" | "CREDIT_CARD" | "SSN" | "PERSON" | etc.

Marks APIEndpoint nodes with:
  exposes_pii: true
  (when any READS/WRITES path from the endpoint reaches a PII field)

Also extracts DataField nodes from source code that weren't captured by Layer 1's
structural parsing (e.g. ORM model fields, Pydantic/TypeScript schema fields).

Usage:
    python -m layer4.pii_detector --repo /path/to/repo --service myapp
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from layer1.neo4j_client import run_query, upsert_node
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── Presidio setup ───────────────────────────────────────────────────────────

def _presidio_available() -> bool:
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: F401
        return True
    except ImportError:
        return False


def _get_analyzer():
    """Return a cached Presidio AnalyzerEngine, or None if not installed."""
    if not hasattr(_get_analyzer, "_instance"):
        if not _presidio_available():
            _get_analyzer._instance = None
        else:
            from presidio_analyzer import AnalyzerEngine
            _get_analyzer._instance = AnalyzerEngine()
    return _get_analyzer._instance


# ─── PII entity types we care about ──────────────────────────────────────────

PII_ENTITY_TYPES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PERSON",
    "LOCATION",
    "DATE_TIME",     # dates of birth in medical context
    "NRP",           # nationality, religion, political affiliation
    "MEDICAL_LICENSE",
    "URL",
]

# Canonical type name mapping (Presidio → LSIG)
_PRESIDIO_TO_LSIG: dict[str, str] = {
    "EMAIL_ADDRESS":     "EMAIL",
    "PHONE_NUMBER":      "PHONE",
    "CREDIT_CARD":       "CREDIT_CARD",
    "US_SSN":            "SSN",
    "US_PASSPORT":       "PASSPORT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "IBAN_CODE":         "BANK_ACCOUNT",
    "IP_ADDRESS":        "IP_ADDRESS",
    "PERSON":            "PERSON_NAME",
    "LOCATION":          "LOCATION",
    "DATE_TIME":         "DATE",
    "NRP":               "SENSITIVE_DEMOGRAPHIC",
    "MEDICAL_LICENSE":   "MEDICAL_ID",
}

# ─── Heuristic name-based PII patterns (fast path, no ML required) ───────────

# Maps compiled regex → PII type
_NAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(email|e_mail|email_address|user_email|contact_email)\b", re.I), "EMAIL"),
    (re.compile(r"\b(phone|phone_number|mobile|cell|telephone|tel)\b", re.I), "PHONE"),
    (re.compile(r"\b(ssn|social_security|social_security_number|tax_id|tin)\b", re.I), "SSN"),
    (re.compile(r"\b(credit_card|card_number|cc_number|pan|card_no|cvv|cvc|expiry)\b", re.I), "CREDIT_CARD"),
    (re.compile(r"\b(password|passwd|pwd|secret|api_key|access_token|refresh_token|auth_token)\b", re.I), "CREDENTIAL"),
    (re.compile(r"\b(dob|date_of_birth|birth_date|birthday|birthdate)\b", re.I), "DATE_OF_BIRTH"),
    (re.compile(r"\b(address|street|zip_code|postal_code|city|state|country)\b", re.I), "ADDRESS"),
    (re.compile(r"\b(first_name|last_name|full_name|given_name|surname|username)\b", re.I), "PERSON_NAME"),
    (re.compile(r"\b(ip_address|ip_addr|remote_addr|client_ip)\b", re.I), "IP_ADDRESS"),
    (re.compile(r"\b(passport|passport_number|national_id|driver_license|dl_number)\b", re.I), "GOVERNMENT_ID"),
    (re.compile(r"\b(iban|bank_account|account_number|routing_number|swift)\b", re.I), "BANK_ACCOUNT"),
    (re.compile(r"\b(health|diagnosis|medical|prescription|patient_id|mrn|insurance)\b", re.I), "HEALTH_DATA"),
    (re.compile(r"\b(salary|income|wage|earnings|tax_return)\b", re.I), "FINANCIAL"),
    (re.compile(r"\b(race|ethnicity|religion|political|sexual_orientation|gender)\b", re.I), "SENSITIVE_DEMOGRAPHIC"),
]


def detect_pii_in_name(field_name: str) -> str | None:
    """Fast regex check on a field/variable name. Returns PII type or None."""
    for pattern, pii_type in _NAME_PATTERNS:
        if pattern.search(field_name):
            return pii_type
    return None


def detect_pii_with_presidio(text: str, score_threshold: float = 0.6) -> list[dict]:
    """
    Run Presidio NLP analysis on a text snippet.
    Returns list of {entity_type, start, end, score} dicts.
    Falls back to empty list if Presidio is not installed.
    """
    analyzer = _get_analyzer()
    if analyzer is None:
        return []

    try:
        results = analyzer.analyze(
            text=text,
            language="en",
            entities=PII_ENTITY_TYPES,
            score_threshold=score_threshold,
        )
        return [
            {
                "entity_type": _PRESIDIO_TO_LSIG.get(r.entity_type, r.entity_type),
                "start": r.start,
                "end": r.end,
                "score": r.score,
            }
            for r in results
        ]
    except Exception as e:
        logger.debug("Presidio analysis failed: %s", e)
        return []


# ─── Source code field extractors ─────────────────────────────────────────────

@dataclass
class ExtractedField:
    name: str
    field_type: str     # declared type annotation or inferred
    file: str
    line: int
    service: str
    context: str        # surrounding ~200 chars for Presidio analysis


# Patterns for extracting field definitions from various frameworks
_FIELD_PATTERNS: dict[str, list[re.Pattern]] = {
    "python": [
        # Django ORM: name = models.CharField(...)
        re.compile(r"^\s*(\w+)\s*=\s*models\.(\w+Field)\(", re.MULTILINE),
        # Pydantic / dataclass: name: type = ...
        re.compile(r"^\s+(\w+)\s*:\s*([\w\[\]|, ]+)\s*(?:=|Field\()", re.MULTILINE),
        # SQLAlchemy: Column(type, ...)
        re.compile(r"(\w+)\s*=\s*(?:mapped_column|Column)\(", re.MULTILINE),
        # TypedDict
        re.compile(r"^\s{4}(\w+)\s*:\s*([\w\[\]]+)", re.MULTILINE),
    ],
    "javascript": [
        # Mongoose schema: fieldName: { type: String }
        re.compile(r"(\w+)\s*:\s*\{?\s*type\s*:", re.MULTILINE),
        # Sequelize: fieldName: DataTypes.STRING
        re.compile(r"(\w+)\s*:\s*DataTypes\.(\w+)", re.MULTILINE),
        # TypeScript interface / type
        re.compile(r"^\s+(?:readonly\s+)?(\w+)\??\s*:\s*([\w\[\]<>|, ]+)\s*;", re.MULTILINE),
    ],
    "typescript": [
        re.compile(r"^\s+(?:readonly\s+)?(\w+)\??\s*:\s*([\w\[\]<>|, ]+)\s*;", re.MULTILINE),
        re.compile(r"@(?:Column|Field|Prop)\([^)]*\)\s+(\w+)\s*[!?]?\s*:\s*([\w\[\]<>]+)", re.MULTILINE),
    ],
    "go": [
        # Struct fields: FieldName string `json:"field_name"`
        re.compile(r"^\s+(\w+)\s+([\w\[\]*]+)\s+`(?:json|db|gorm):", re.MULTILINE),
    ],
    "java": [
        # JPA/Hibernate: private String fieldName;
        re.compile(r"(?:private|protected|public)\s+([\w<>]+)\s+(\w+)\s*;", re.MULTILINE),
        # @Column annotation
        re.compile(r"@Column[^)]*\)\s+(?:private\s+)?[\w<>]+\s+(\w+)", re.MULTILINE),
    ],
    "ruby": [
        # ActiveRecord: t.string :field_name
        re.compile(r"t\.(\w+)\s+:(\w+)", re.MULTILINE),
        # attr_accessor :field_name
        re.compile(r"attr_(?:accessor|reader|writer)\s+:(\w+)", re.MULTILINE),
    ],
}

_LANG_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".java": "java", ".rb": "ruby",
}


def extract_fields_from_source(
    source: str, language: str, file_path: str, service: str
) -> list[ExtractedField]:
    """Extract declared fields from source using language-specific patterns."""
    patterns = _FIELD_PATTERNS.get(language, [])
    fields: list[ExtractedField] = []
    lines = source.splitlines()

    for pattern in patterns:
        for m in pattern.finditer(source):
            groups = [g for g in m.groups() if g]
            if not groups:
                continue

            # Field name is typically the first or second group depending on pattern
            name = groups[0] if language != "java" else groups[-1]
            field_type = groups[1] if len(groups) > 1 else "unknown"

            line_no = source[:m.start()].count("\n") + 1

            # Extract surrounding context for Presidio
            start_ctx = max(0, m.start() - 100)
            end_ctx = min(len(source), m.end() + 100)
            context = source[start_ctx:end_ctx]

            if name and len(name) > 1:  # skip single-char variable names
                fields.append(ExtractedField(
                    name=name, field_type=field_type,
                    file=file_path, line=line_no,
                    service=service, context=context,
                ))

    return fields


# ─── PII annotation pipeline ─────────────────────────────────────────────────

def analyse_field(field: ExtractedField) -> tuple[bool, str | None]:
    """
    Determine whether a field is PII-likely.
    Returns (pii_likely, pii_type).
    Uses fast regex first, falls back to Presidio NLP.
    """
    # Fast path: name-based detection
    pii_type = detect_pii_in_name(field.name)
    if pii_type:
        return True, pii_type

    # Slow path: Presidio NLP on context
    if field.context:
        results = detect_pii_with_presidio(field.name + " " + field.context[:200])
        if results:
            # Take highest-confidence entity
            best = max(results, key=lambda r: r["score"])
            return True, best["entity_type"]

    return False, None


def _upsert_data_field(field: ExtractedField, pii_likely: bool, pii_type: str | None) -> str:
    """Create or update a DataField node. Returns the node ID."""
    field_id = f"{field.service}:{field.name}"
    upsert_node(
        "DataField",
        id_props={"id": field_id},
        extra_props={
            "name": field.name,
            "type": field.field_type,
            "file": field.file,
            "line": field.line,
            "service": field.service,
            "pii_likely": pii_likely,
            "pii_type": pii_type,
        },
    )
    # Link the Function that defines this field via WRITES
    run_query(
        """
        MATCH (f:Function {service: $svc, file: $file})
        WHERE f.line <= $line AND f.deprecated_at IS NULL
        WITH f ORDER BY f.line DESC LIMIT 1
        MATCH (d:DataField {id: $field_id})
        MERGE (f)-[:WRITES]->(d)
        """,
        {"svc": field.service, "file": field.file, "line": field.line, "field_id": field_id},
    )
    return field_id


def _mark_endpoints_exposing_pii(service: str) -> int:
    """
    Mark APIEndpoint nodes as exposes_pii=true if any READS/WRITES path from
    the endpoint leads to a PII DataField.
    Returns number of endpoints marked.
    """
    result = run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(h:Function)
        MATCH (h)-[:CALLS*0..8]->(f:Function)-[:READS|WRITES]->(d:DataField {pii_likely: true})
        WHERE ep.deprecated_at IS NULL
        SET ep.exposes_pii = true
        RETURN count(DISTINCT ep) AS cnt
        """,
        {"svc": service},
    )
    count = result[0]["cnt"] if result else 0
    logger.info("Marked %d APIEndpoints as exposes_pii for service=%s", count, service)
    return count


# ─── Main pipeline ────────────────────────────────────────────────────────────

def _iter_source_files(repo_dir: Path) -> Iterator[tuple[Path, str]]:
    """Yield (path, language) for all supported source files."""
    skip_dirs = {".git", "node_modules", "__pycache__", "vendor", ".venv", "dist", "build"}
    for p in repo_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        lang = _LANG_EXTENSIONS.get(p.suffix)
        if lang:
            yield p, lang


def scan(repo_dir: str | Path, service: str) -> dict:
    """
    Scan a repository's source code for PII fields and annotate the graph.

    Returns a summary dict.
    """
    repo = Path(repo_dir)
    total_fields = 0
    pii_fields = 0
    files_scanned = 0

    for src_path, language in _iter_source_files(repo):
        rel_path = str(src_path.relative_to(repo)).replace("\\", "/")
        try:
            source = src_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        fields = extract_fields_from_source(source, language, rel_path, service)
        files_scanned += 1

        for field in fields:
            pii_likely, pii_type = analyse_field(field)
            _upsert_data_field(field, pii_likely, pii_type)
            total_fields += 1
            if pii_likely:
                pii_fields += 1

    # After all fields are upserted, propagate exposes_pii to endpoints
    endpoints_marked = _mark_endpoints_exposing_pii(service)

    summary = {
        "status": "ok",
        "service": service,
        "files_scanned": files_scanned,
        "fields_extracted": total_fields,
        "pii_fields_detected": pii_fields,
        "endpoints_marked_pii": endpoints_marked,
    }
    logger.info("PII scan complete: %s", summary)
    return summary


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(description="LSIG Layer 4 — PII Detector")
    parser.add_argument("--repo", required=True, help="Local repo path")
    parser.add_argument("--service", required=True, help="Service name")
    args = parser.parse_args()
    print(json.dumps(scan(args.repo, args.service), indent=2))
