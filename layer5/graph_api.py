"""
Layer 5 — Unified Graph Query API.

Single FastAPI application that unifies all query surfaces:
  - Raw Cypher (admin only)
  - Natural language (Claude NL→Cypher)
  - Pre-built service summary
  - Pre-built change impact analysis (calls all layer APIs)
  - Weaviate fuzzy search
  - VictoriaMetrics time-series

All endpoints require a valid Keycloak JWT (X-Auth-Token header validated by
the auth middleware). The raw Cypher endpoint requires the "admin" role.

Run:
    uvicorn layer5.graph_api:app --host 0.0.0.0 --port 8005 --reload

This API is exposed to the React dashboard and the Change Impact Certificate
engine (Layer 6). The Layer 1 code_api runs separately on port 8001.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Body, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import anthropic

from layer1.neo4j_client import run_query
from layer5.nl_to_cypher import translate_and_execute, validate_cypher, warm_schema_cache
from layer5.weaviate_index import get_index, SearchResult
from layer5.victoria_metrics import get_client as get_vm

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── Lifespan: warm caches on startup ────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Layer 5 Graph API starting up …")
    # Warm the Claude schema prompt cache in the background
    try:
        warm_schema_cache()
        logger.info("Schema prompt cache warmed")
    except Exception as e:
        logger.warning("Schema cache warm-up failed (non-fatal): %s", e)

    # Ensure Weaviate schema exists
    try:
        get_index().ensure_schema()
        logger.info("Weaviate schema ready")
    except Exception as e:
        logger.warning("Weaviate schema init failed (non-fatal): %s", e)

    yield
    logger.info("Layer 5 Graph API shutting down")


app = FastAPI(
    title="LSIG Unified Graph Query API",
    version="1.0.0",
    description="Natural language and structured queries over the LSIG knowledge graph.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Auth stub (full Keycloak integration in Layer 7) ────────────────────────

async def _require_auth(request: Request) -> dict:
    """
    Validates X-Auth-Token JWT against Keycloak.
    In dev mode (LSIG_AUTH_DISABLED=true) skips validation.
    """
    if os.environ.get("LSIG_AUTH_DISABLED", "").lower() == "true":
        return {"sub": "dev-user", "roles": ["admin", "reader"]}

    token = request.headers.get("X-Auth-Token") or request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing X-Auth-Token header")
    # TODO: validate JWT against Keycloak JWKS URI (Layer 7)
    return {"sub": "authenticated", "roles": ["reader"]}


async def _require_admin(request: Request) -> dict:
    """Require the 'admin' role — used for raw Cypher endpoint."""
    claims = await _require_auth(request)
    if "admin" not in claims.get("roles", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Admin role required for raw Cypher queries")
    return claims


# ─── Error helper ─────────────────────────────────────────────────────────────

def _error(status_code: int, what: str, layer: str, input_hint: str, action: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={
        "error": {"what": what, "layer": layer, "input": input_hint, "action": action}
    })


@app.exception_handler(Exception)
async def _global_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url)
    return _error(500, str(exc), "layer5:graph_api", str(request.url),
                  "Check LSIG Graph API logs.")


# ─── /query endpoints ─────────────────────────────────────────────────────────

@app.post("/query/cypher")
async def raw_cypher(
    cypher: str = Body(..., embed=True, description="Cypher query to execute"),
    params: dict = Body(default={}, embed=True),
    _claims: dict = Depends(_require_admin),
) -> dict:
    """
    Execute a raw Cypher query (admin only).
    Read operations only — write operations are blocked at the Neo4j user level.
    """
    valid, err = validate_cypher(cypher)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Unsafe query: {err}")
    try:
        records = run_query(cypher, params)
        return {"record_count": len(records), "records": records}
    except Exception as e:
        return _error(400, str(e), "layer5:cypher", cypher[:100],
                      "Check Cypher syntax and parameter names.")


@app.post("/query/nl")
async def nl_query(
    question: str = Body(..., embed=True, description="Natural language question"),
    params: dict = Body(default={}, embed=True),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """
    Translate a natural language question to Cypher and execute it.
    Returns the generated Cypher, result records, and a plain-English summary.
    """
    if not question.strip():
        raise HTTPException(status_code=400, detail="question must not be empty")

    result = translate_and_execute(question, extra_params=params)

    if result.error:
        return _error(
            422, result.error, "layer5:nl_query", question[:120],
            "Rephrase the question or use /query/cypher for precise queries.",
        )

    return {
        "question": result.question,
        "cypher": result.cypher,
        "record_count": result.record_count,
        "records": result.records,
        "summary": result.summary,
        "cache_hit": result.cached,
        "latency_ms": result.latency_ms,
    }


@app.get("/query/service_summary")
async def service_summary(
    service: str = Query(...),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """
    Full health snapshot for a service — aggregates data from all four layers.
    """
    # Layer 1: code graph stats
    graph_stats = run_query(
        """
        MATCH (f:Function {service: $svc}) WHERE f.deprecated_at IS NULL
        WITH count(f) AS function_count
        MATCH (ep:APIEndpoint {service: $svc}) WHERE ep.deprecated_at IS NULL
        RETURN function_count, count(ep) AS endpoint_count
        """,
        {"svc": service},
    )
    stats = graph_stats[0] if graph_stats else {}

    # Layer 2: runtime coverage
    runtime = run_query(
        """
        MATCH (f:Function {service: $svc})
        WHERE f.deprecated_at IS NULL
        OPTIONAL MATCH (f)-[r:RUNTIME_CALLS]->(f)
        RETURN
            count(DISTINCT CASE WHEN r IS NOT NULL THEN f END) AS live_functions,
            count(DISTINCT CASE WHEN r IS NULL THEN f END) AS dead_functions,
            sum(r.call_count_24h) AS total_calls_24h
        """,
        {"svc": service},
    )
    rt = runtime[0] if runtime else {}

    # Layer 3: security posture
    security = run_query(
        """
        MATCH (d:Dependency {service: $svc})-[r:HAS_VULN]->(v:Vulnerability)
        WHERE d.deprecated_at IS NULL
        RETURN r.reachability AS reachability, count(*) AS count
        ORDER BY reachability
        """,
        {"svc": service},
    )
    vuln_breakdown = {row["reachability"]: row["count"] for row in security}

    # Layer 4: PII and ownership
    pii = run_query(
        """
        MATCH (d:DataField {service: $svc, pii_likely: true})
        WHERE d.deprecated_at IS NULL
        RETURN count(d) AS pii_field_count,
               collect(DISTINCT d.pii_type) AS pii_types
        """,
        {"svc": service},
    )
    pii_data = pii[0] if pii else {}

    regulatory = run_query(
        "MATCH (s:Service {id: $svc}) RETURN s.regulatory_scope AS scope, "
        "s.scope_confidence AS confidence",
        {"svc": service},
    )
    reg_data = regulatory[0] if regulatory else {}

    # Layer 4: ownership
    owners = run_query(
        """
        MATCH (f:Function {service: $svc})
        WHERE f.deprecated_at IS NULL AND f.owner_team IS NOT NULL
        RETURN f.owner_team AS team, count(f) AS functions
        ORDER BY functions DESC LIMIT 5
        """,
        {"svc": service},
    )

    # VictoriaMetrics: p95 certificate duration
    vm = get_vm()
    cert_p95 = vm.query_certificate_p95(days=7)

    return {
        "service": service,
        "graph": {
            "function_count": stats.get("function_count", 0),
            "endpoint_count": stats.get("endpoint_count", 0),
        },
        "runtime": {
            "live_functions": rt.get("live_functions", 0),
            "dead_functions": rt.get("dead_functions", 0),
            "total_calls_24h": rt.get("total_calls_24h", 0),
        },
        "security": {
            "vulnerability_breakdown": vuln_breakdown,
            "critical_count": vuln_breakdown.get("CRITICAL", 0),
            "high_count": vuln_breakdown.get("HIGH", 0),
        },
        "pii": {
            "pii_field_count": pii_data.get("pii_field_count", 0),
            "pii_types": pii_data.get("pii_types", []),
        },
        "regulatory": {
            "scope": reg_data.get("scope", ["NONE"]),
            "confidence": reg_data.get("confidence", "LOW"),
        },
        "ownership": {"top_teams": owners},
        "metrics": {
            "certificate_p95_seconds": cert_p95,
        },
    }


@app.get("/query/change_impact")
async def change_impact(
    pr_id: str = Query(..., description="Pull request identifier"),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """
    Pre-merge impact analysis for a PR.
    Aggregates all layer APIs: code delta, runtime blast radius, security delta,
    PII flow delta, and ownership.

    Requires the PR to have been pre-processed by the webhook receiver (Layer 6)
    which populates a PullRequest node with changed_function_ids.
    """
    pr_rows = run_query(
        "MATCH (pr:PullRequest {id: $pr_id}) "
        "RETURN pr.service AS service, pr.changed_function_ids AS func_ids, "
        "pr.changed_files AS changed_files, pr.author AS author",
        {"pr_id": pr_id},
    )
    if not pr_rows:
        raise HTTPException(
            status_code=404,
            detail=f"PR {pr_id} not found. Ensure the webhook receiver has processed it.",
        )
    pr = pr_rows[0]
    service = pr["service"]
    func_ids = pr.get("func_ids") or []

    # Code delta
    code_delta = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})
        OPTIONAL MATCH (callers:Function)-[:CALLS]->(f)
        OPTIONAL MATCH (f)-[:CALLS]->(callees:Function)
        RETURN
            f.id AS id, f.name AS name, f.file AS file,
            count(DISTINCT callers) AS caller_count,
            count(DISTINCT callees) AS callee_count
        """,
        {"fids": func_ids},
    )

    # Runtime blast radius
    blast_radius = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})-[r:RUNTIME_CALLS]->(f)
        RETURN f.id AS func_id, r.call_count_24h AS calls_24h
        ORDER BY calls_24h DESC
        """,
        {"fids": func_ids},
    )
    total_calls = sum(r["calls_24h"] or 0 for r in blast_radius)
    global_calls_row = run_query(
        "MATCH ()-[r:RUNTIME_CALLS]->() RETURN sum(r.call_count_24h) AS total"
    )
    global_calls = (global_calls_row[0]["total"] or 0) if global_calls_row else 0
    blast_pct = round((total_calls / global_calls) * 100, 2) if global_calls else 0.0

    # Security delta
    from layer3.reachability import compute_pr_security_delta
    sec_delta = compute_pr_security_delta(func_ids, service)

    # PII flow delta — check if any changed function now writes to a new PII field
    pii_delta = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})-[:WRITES]->(d:DataField {pii_likely: true})
        WHERE d.deprecated_at IS NULL
        RETURN DISTINCT d.id AS field_id, d.name AS field_name, d.pii_type AS pii_type
        """,
        {"fids": func_ids},
    )

    # Unregulated PII flows introduced
    unregulated = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})-[:WRITES]->(src:DataField {pii_likely: true})
        MATCH (src)-[r:FLOWS_TO {unregulated: true}]->(dst:DataField)
        RETURN DISTINCT src.name AS src_field, dst.service AS dst_service,
               r.via_endpoint AS via, r.service_path AS path
        """,
        {"fids": func_ids},
    )

    # Ownership of changed functions
    ownership = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})
        RETURN f.id AS id, f.owner_team AS team, f.owner_email AS email
        """,
        {"fids": func_ids},
    )

    return {
        "pr_id": pr_id,
        "service": service,
        "author": pr.get("author"),
        "changed_files": pr.get("changed_files", []),
        "code_delta": {
            "changed_functions": len(func_ids),
            "functions": code_delta,
        },
        "runtime": {
            "blast_radius_pct": blast_pct,
            "calls_24h_on_changed_path": total_calls,
            "hot_functions": blast_radius[:5],
        },
        "security": {
            "new_cve_exposures": sec_delta["new_exposures"],
            "removed_cve_exposures": sec_delta["removed_exposures"],
            "net_change": len(sec_delta["new_exposures"]) - len(sec_delta["removed_exposures"]),
        },
        "pii": {
            "new_pii_writes": pii_delta,
            "unregulated_flows": unregulated,
        },
        "ownership": ownership,
    }


# ─── /search endpoints (Weaviate fuzzy search) ────────────────────────────────

@app.get("/search/functions")
async def search_functions(
    q: str = Query(..., description="Semantic search query"),
    service: str = Query(None),
    limit: int = Query(10, ge=1, le=50),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """Fuzzy search for Function nodes using vector similarity."""
    try:
        results = get_index().search_functions(q, limit=limit, service=service)
    except Exception as e:
        logger.warning("Weaviate function search failed: %s", e)
        results = []

    # Enrich with Neo4j data for matched node IDs
    neo4j_ids = [r.neo4j_id for r in results]
    enriched = _enrich_functions(neo4j_ids) if neo4j_ids else []

    return {
        "query": q,
        "count": len(results),
        "results": [
            {**_result_to_dict(r), **_find_enriched(enriched, r.neo4j_id)}
            for r in results
        ],
    }


@app.get("/search/endpoints")
async def search_endpoints(
    q: str = Query(..., description="Semantic search query"),
    service: str = Query(None),
    limit: int = Query(10, ge=1, le=50),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """Fuzzy search for APIEndpoint nodes using vector similarity."""
    try:
        results = get_index().search_endpoints(q, limit=limit, service=service)
    except Exception as e:
        logger.warning("Weaviate endpoint search failed: %s", e)
        results = []

    neo4j_ids = [r.neo4j_id for r in results]
    enriched = _enrich_endpoints(neo4j_ids) if neo4j_ids else []

    return {
        "query": q,
        "count": len(results),
        "results": [
            {**_result_to_dict(r), **_find_enriched(enriched, r.neo4j_id)}
            for r in results
        ],
    }


@app.get("/search/vulnerabilities")
async def search_vulnerabilities(
    q: str = Query(..., description="Semantic search query — e.g. 'SQL injection'"),
    limit: int = Query(10, ge=1, le=50),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """Fuzzy search for Vulnerability nodes using vector similarity."""
    try:
        results = get_index().search_vulnerabilities(q, limit=limit)
    except Exception as e:
        logger.warning("Weaviate vuln search failed: %s", e)
        results = []

    neo4j_ids = [r.neo4j_id for r in results]
    enriched = _enrich_vulns(neo4j_ids) if neo4j_ids else []

    return {
        "query": q,
        "count": len(results),
        "results": [
            {**_result_to_dict(r), **_find_enriched(enriched, r.neo4j_id)}
            for r in results
        ],
    }


@app.get("/search/all")
async def search_all(
    q: str = Query(...),
    limit: int = Query(5, ge=1, le=20),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """Cross-type semantic search across Functions, Endpoints, and Vulnerabilities."""
    try:
        results = get_index().search_all(q, limit=limit)
    except Exception as e:
        logger.warning("Weaviate search_all failed: %s", e)
        results = []
    return {
        "query": q,
        "count": len(results),
        "results": [_result_to_dict(r) for r in results],
    }


# ─── /metrics endpoints (VictoriaMetrics) ────────────────────────────────────

@app.get("/metrics/call_history")
async def call_history(
    service: str = Query(...),
    function_name: str = Query(...),
    days: int = Query(7, ge=1, le=30),
    _claims: dict = Depends(_require_auth),
) -> dict:
    """Return call count time series for a function from VictoriaMetrics."""
    vm = get_vm()
    series = vm.query_call_history(service, function_name, days)
    if series is None:
        return {"service": service, "function": function_name, "data_points": []}
    return {
        "service": service,
        "function": function_name,
        "days": days,
        "data_points": [
            {"timestamp": ts, "calls": val}
            for ts, val in zip(series.timestamps, series.values)
        ],
    }


@app.get("/metrics/system")
async def system_metrics(_claims: dict = Depends(_require_auth)) -> dict:
    """Return LSIG system health metrics from VictoriaMetrics."""
    vm = get_vm()
    return {
        "certificate_p95_seconds": vm.query_certificate_p95(),
        "false_positive_reduction_rate": vm.query_false_positive_reduction_rate(),
        "victoriametrics_healthy": vm.health(),
    }


@app.post("/search/index/sync")
async def sync_search_index(
    service: str = Query(None, description="Sync specific service only"),
    _claims: dict = Depends(_require_admin),
) -> dict:
    """Trigger a Weaviate index synchronisation from Neo4j (admin only)."""
    try:
        counts = get_index().sync_from_neo4j(service=service)
        return {"status": "ok", "synced": counts}
    except Exception as e:
        return _error(500, str(e), "layer5:weaviate_sync", service or "all",
                      "Check Weaviate connectivity and logs.")


# ─── Enrichment helpers ───────────────────────────────────────────────────────

def _result_to_dict(r: SearchResult) -> dict:
    return {
        "neo4j_id": r.neo4j_id,
        "description": r.description,
        "certainty": round(r.certainty, 3),
        "node_type": r.node_type,
    }


def _find_enriched(enriched: list[dict], neo4j_id: str) -> dict:
    return next((e for e in enriched if e.get("id") == neo4j_id), {})


def _enrich_functions(ids: list[str]) -> list[dict]:
    return run_query(
        "UNWIND $ids AS id MATCH (f:Function {id: id}) "
        "RETURN f.id AS id, f.name AS name, f.file AS file, "
        "f.line AS line, f.service AS service, f.owner_team AS owner_team",
        {"ids": ids},
    )


def _enrich_endpoints(ids: list[str]) -> list[dict]:
    return run_query(
        "UNWIND $ids AS id MATCH (ep:APIEndpoint {id: id}) "
        "RETURN ep.id AS id, ep.path AS path, ep.method AS method, "
        "ep.service AS service, ep.exposes_pii AS exposes_pii",
        {"ids": ids},
    )


def _enrich_vulns(ids: list[str]) -> list[dict]:
    return run_query(
        "UNWIND $ids AS id MATCH (v:Vulnerability {id: id}) "
        "RETURN v.id AS id, v.cve_id AS cve_id, v.severity AS severity, "
        "v.epss_score AS epss_score, v.in_kev AS in_kev",
        {"ids": ids},
    )
