"""
Layer 5 — Natural Language to Cypher Translator.

Translates plain-English questions about the LSIG knowledge graph into
executable Neo4j Cypher queries using the Claude API (claude-sonnet-4-6).

Key design decisions:
  - The full Neo4j schema is included in every request as a system prompt.
  - Prompt caching is applied to the schema context block (it is large and
    static between queries — cache hit rate typically >90%).
  - The translator validates the generated Cypher for basic safety before
    executing it (no WRITE operations allowed through this path).
  - Results are returned as both raw records and a plain-English summary.

Usage:
    from layer5.nl_to_cypher import translate_and_execute
    result = translate_and_execute("Which services have CRITICAL CVEs reachable from the internet?")
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import anthropic

from layer1.neo4j_client import run_query
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)

# ─── Schema context (cached as a prompt cache block) ─────────────────────────

# This is the authoritative schema reference fed to Claude on every NL query.
# It must be kept in sync with schema/v1_init.cypher.
# Wrapped in XML tags so Claude can reference it precisely.
LSIG_SCHEMA_CONTEXT = """
<lsig_schema>
## LSIG Neo4j Knowledge Graph Schema

### Node Types

**Function** `{id, name, file, line, language, service, owner_team, owner_email, deprecated_at}`
- Represents a function or method in source code.

**Module** `{id, name, path, service, owner_team, owner_email, deprecated_at}`
- Represents a source file or module.

**APIEndpoint** `{id, path, method, service, authenticated, exposes_pii, pci_scope, hipaa_scope, owner_team, owner_email, deprecated_at}`
- An externally-facing HTTP/async API endpoint.
- `method`: GET | POST | PUT | PATCH | DELETE | SUBSCRIBE | PUBLISH
- `authenticated`: boolean
- `exposes_pii`: boolean — true if any read/write path reaches a PII DataField

**DataField** `{id, name, type, pii_likely, pii_type, service, file, line, deprecated_at}`
- A field in a data model, schema, or ORM class.
- `pii_type`: EMAIL | PHONE | CREDIT_CARD | SSN | PERSON_NAME | ADDRESS | HEALTH_DATA | CREDENTIAL | IP_ADDRESS | GOVERNMENT_ID | BANK_ACCOUNT | DATE_OF_BIRTH | FINANCIAL | SENSITIVE_DEMOGRAPHIC | null

**Dependency** `{id, name, version, ecosystem, service, purl, cpe, deprecated_at}`
- A third-party library dependency of a service.
- `ecosystem`: pypi | npm | go | maven | gem | cargo | nuget | deb | apk

**Vulnerability** `{id, cve_id, osv_id, affected_package, affected_versions[], vulnerable_functions[], severity, epss_score, in_kev, published_at, deprecated_at}`
- A known security vulnerability.
- `severity`: CRITICAL | HIGH | MEDIUM | LOW
- `in_kev`: boolean — true if listed in CISA Known Exploited Vulnerabilities

**Service** `{id, name, repo_url, language, regulatory_scope[], scope_confidence, external_url, deprecated_at}`
- A logical microservice or application.
- `regulatory_scope`: ["PCI"] | ["HIPAA"] | ["GDPR"] | ["SOC2"] | ["NONE"]

**ExternalEndpoint** `{id, url, path, service, template_id, severity, discovered_at, deprecated_at}`
- An internet-reachable endpoint discovered by Nuclei scanning.

**SchemaVersion** `{version, applied_at, description}`

### Relationship Types

```
(Function)-[:CALLS]->(Function)
(Function)-[:READS]->(DataField)
(Function)-[:WRITES]->(DataField)
(Module)-[:IMPORTS]->(Dependency)
(APIEndpoint)-[:HANDLED_BY]->(Function)
(Dependency)-[:HAS_VULN {severity, epss_score, in_kev, reachability}]->(Vulnerability)
(Function)-[:RUNTIME_CALLS {last_seen, call_count_24h, call_count_7d}]->(Function)
(DataField)-[:FLOWS_TO {via_endpoint, service_path, regulated, unregulated}]->(DataField)
(Service)-[:USES_DEPENDENCY]->(Dependency)
(ExternalEndpoint)-[:MAPS_TO]->(APIEndpoint)
```

### HAS_VULN relationship properties
- `reachability`: CRITICAL | HIGH | MEDIUM | LOW | NOT_REACHABLE | UNKNOWN
- `severity`: CRITICAL | HIGH | MEDIUM | LOW
- `epss_score`: float 0.0–1.0 (exploitation probability)
- `in_kev`: boolean

### Filtering conventions
- Always add `WHERE n.deprecated_at IS NULL` to exclude deprecated nodes.
- Use `LIMIT` clauses (default 50) to avoid excessive result sets.
- Prefer `DISTINCT` when aggregating across relationships.

### Common query patterns

**Services with CRITICAL reachable CVEs owned by a specific team:**
```cypher
MATCH (d:Dependency)-[r:HAS_VULN]->(v:Vulnerability)
WHERE r.reachability = 'CRITICAL' AND d.deprecated_at IS NULL
MATCH (ep:APIEndpoint {service: d.service})
WHERE ep.owner_team = '@myorg/platform' AND ep.deprecated_at IS NULL
RETURN DISTINCT d.service AS service, v.cve_id AS cve, r.epss_score AS epss
ORDER BY r.epss_score DESC
```

**PII flows to unregulated services:**
```cypher
MATCH (src:DataField {pii_likely: true})-[r:FLOWS_TO {unregulated: true}]->(dst:DataField)
WHERE src.deprecated_at IS NULL
RETURN src.service AS source_service, src.pii_type AS pii_type,
       dst.service AS dest_service, r.via_endpoint AS via
```

**Dead code functions:**
```cypher
MATCH (f:Function {service: $service})
WHERE f.deprecated_at IS NULL
  AND NOT (f)-[:RUNTIME_CALLS]->()
  AND NOT ()-[:CALLS]->(f)
RETURN f.name, f.file, f.line
```
</lsig_schema>
"""

# ─── Claude client ────────────────────────────────────────────────────────────

def _get_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Set it in your deployment values.yaml or local .env file."
        )
    return anthropic.Anthropic(api_key=api_key)


# ─── Cypher safety validator ──────────────────────────────────────────────────

# Patterns that indicate a write operation — block them in the NL query path.
_WRITE_PATTERNS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH|DROP|CALL\s+apoc\.periodic|"
    r"CALL\s+db\.schema|LOAD\s+CSV)\b",
    re.IGNORECASE,
)

# Patterns Claude might hallucinate that aren't valid Cypher
_PLACEHOLDER_PATTERNS = re.compile(r"\$\{[^}]+\}|<[A-Z_]+>")


def validate_cypher(query: str) -> tuple[bool, str]:
    """
    Return (is_valid, error_message).
    A query is invalid if it contains write operations or placeholder syntax.
    """
    if _WRITE_PATTERNS.search(query):
        return False, "Query contains write operations — only read queries are permitted via NL path."
    if _PLACEHOLDER_PATTERNS.search(query):
        return False, "Query contains unfilled placeholders — the generated Cypher is incomplete."
    if len(query.strip()) < 10:
        return False, "Generated query is too short to be valid."
    return True, ""


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class NLQueryResult:
    question: str
    cypher: str
    records: list[dict]
    summary: str
    cached: bool        # True if the schema context was served from cache
    latency_ms: int
    record_count: int
    error: str | None = None


# ─── Main translation + execution ────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a Neo4j Cypher query expert for the LSIG (Live System Intelligence Graph) "
    "platform. Given a natural language question, generate a single valid read-only Cypher "
    "query that answers it using the schema provided. "
    "Rules:\n"
    "1. Output ONLY the Cypher query — no explanation, no markdown fences, no comments.\n"
    "2. Always filter deprecated nodes: `WHERE n.deprecated_at IS NULL`.\n"
    "3. Use LIMIT 50 unless the question explicitly asks for more or all results.\n"
    "4. Never use WRITE operations (CREATE, MERGE, SET, DELETE, REMOVE).\n"
    "5. Use parameter syntax ($param) for any user-supplied values embedded in the query.\n"
    "6. Prefer DISTINCT to avoid duplicates in aggregations.\n"
    "7. If the question cannot be answered with the given schema, return: "
    "MATCH (n:SchemaVersion) RETURN 'UNSUPPORTED_QUERY' AS error LIMIT 1\n"
)

_SUMMARY_SYSTEM_PROMPT = (
    "You are a senior security and engineering analyst. Given a question and its query "
    "results from a live code intelligence graph, write a concise 2-3 sentence plain-English "
    "summary of the findings. Be direct about risk implications. "
    "If results are empty, say so clearly and suggest what that implies."
)


def translate_and_execute(
    question: str,
    extra_params: dict | None = None,
    max_records: int = 100,
) -> NLQueryResult:
    """
    Translate a natural language question to Cypher, execute it, and return
    structured results with a plain-English summary.

    The schema context is sent with cache_control=ephemeral so the Anthropic
    API caches it across calls in the same session (5-minute TTL).

    Args:
        question:      Plain-English question about the LSIG graph.
        extra_params:  Optional Cypher parameters to inject (e.g. {"service": "myapp"}).
        max_records:   Cap on records returned to the caller.
    """
    client = _get_client()
    start = time.monotonic()

    # ── Step 1: Generate Cypher ───────────────────────────────────────────────
    def _call_claude_cypher():
        return client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": [
                        # Schema block — marked for prompt caching
                        {
                            "type": "text",
                            "text": LSIG_SCHEMA_CONTEXT,
                            "cache_control": {"type": "ephemeral"},
                        },
                        # The actual question
                        {
                            "type": "text",
                            "text": f"Question: {question}",
                        },
                    ],
                }
            ],
        )

    try:
        cypher_response = with_retry(
            _call_claude_cypher,
            label="claude:nl_to_cypher",
            max_attempts=3,
            exceptions=(anthropic.APIError, anthropic.RateLimitError, Exception),
        )
    except Exception as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        return NLQueryResult(
            question=question, cypher="", records=[], summary="",
            cached=False, latency_ms=latency_ms, record_count=0,
            error=f"Claude API error during Cypher generation: {e}",
        )

    raw_cypher = cypher_response.content[0].text.strip()
    # Strip markdown fences if Claude added them despite instructions
    raw_cypher = re.sub(r"^```(?:cypher)?\s*", "", raw_cypher, flags=re.IGNORECASE)
    raw_cypher = re.sub(r"\s*```$", "", raw_cypher)
    raw_cypher = raw_cypher.strip()

    # Track whether cache was hit (Anthropic returns cache_read_input_tokens > 0)
    usage = cypher_response.usage
    cache_hit = getattr(usage, "cache_read_input_tokens", 0) > 0

    # ── Step 2: Validate ──────────────────────────────────────────────────────
    valid, err = validate_cypher(raw_cypher)
    if not valid:
        latency_ms = int((time.monotonic() - start) * 1000)
        return NLQueryResult(
            question=question, cypher=raw_cypher, records=[], summary="",
            cached=cache_hit, latency_ms=latency_ms, record_count=0,
            error=f"Generated Cypher failed validation: {err}",
        )

    # ── Step 3: Execute ───────────────────────────────────────────────────────
    try:
        records = run_query(raw_cypher, extra_params or {})[:max_records]
    except Exception as e:
        latency_ms = int((time.monotonic() - start) * 1000)
        return NLQueryResult(
            question=question, cypher=raw_cypher, records=[], summary="",
            cached=cache_hit, latency_ms=latency_ms, record_count=0,
            error=f"Cypher execution error: {e}",
        )

    # ── Step 4: Summarise ─────────────────────────────────────────────────────
    summary = _summarise_results(client, question, raw_cypher, records)

    latency_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "NL query completed question=%r cypher_len=%d records=%d "
        "cache_hit=%s latency_ms=%d",
        question[:60], len(raw_cypher), len(records), cache_hit, latency_ms,
    )

    return NLQueryResult(
        question=question,
        cypher=raw_cypher,
        records=records,
        summary=summary,
        cached=cache_hit,
        latency_ms=latency_ms,
        record_count=len(records),
    )


def _summarise_results(
    client: anthropic.Anthropic,
    question: str,
    cypher: str,
    records: list[dict],
) -> str:
    """Generate a 2-3 sentence plain-English summary of query results."""
    # Truncate records to avoid exceeding token limits
    sample = records[:20]
    records_text = json.dumps(sample, indent=2, default=str)
    if len(records) > 20:
        records_text += f"\n... and {len(records) - 20} more records."

    prompt = (
        f"Question: {question}\n\n"
        f"Cypher query executed:\n{cypher}\n\n"
        f"Results ({len(records)} records):\n{records_text}"
    )

    def _call():
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=300,
            system=_SUMMARY_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()

    try:
        return with_retry(_call, label="claude:summarise", max_attempts=2,
                          exceptions=(anthropic.APIError, Exception))
    except Exception as e:
        logger.warning("Summary generation failed: %s", e)
        return f"{len(records)} records returned. Summary generation failed: {e}"


# ─── Batch schema warm-up ─────────────────────────────────────────────────────

def warm_schema_cache() -> bool:
    """
    Send a no-op query to pre-populate the Anthropic prompt cache with the
    schema context block. Call once at API startup.
    Returns True if the cache was populated, False on error.
    """
    try:
        result = translate_and_execute(
            "How many Service nodes exist?",
            max_records=1,
        )
        logger.info(
            "Schema cache warmed — cached=%s latency_ms=%d",
            result.cached, result.latency_ms,
        )
        return True
    except Exception as e:
        logger.warning("Schema cache warm-up failed: %s", e)
        return False
