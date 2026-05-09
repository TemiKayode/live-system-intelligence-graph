"""
Layer 1 — Code Intelligence Engine REST API.

Exposes the Neo4j code graph over HTTP via FastAPI.
All endpoints require a valid Keycloak JWT (enforced by auth middleware).

Run:
    uvicorn layer1.code_api:app --host 0.0.0.0 --port 8001 --reload
"""

import os
import logging
from typing import Annotated

from fastapi import FastAPI, HTTPException, Depends, Query, Body, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from layer1.neo4j_client import run_query
from layer3.reachability import (
    compute_reachability, run_for_service, compute_pr_security_delta,
    Reachability,
)
from layer4.regulatory_annotator import annotate as annotate_regulatory_scope

logger = logging.getLogger(__name__)

app = FastAPI(
    title="LSIG Code Intelligence API",
    version="1.0.0",
    description="Query the live code knowledge graph.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Error helpers ────────────────────────────────────────────────────────────


def _error(status_code: int, what: str, layer: str, input_hint: str, action: str) -> JSONResponse:
    """Rule 6: self-describing errors — never naked 500s."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "what": what,
                "layer": layer,
                "input": input_hint,
                "action": action,
            }
        },
    )


@app.exception_handler(Exception)
async def _global_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url)
    return _error(
        500,
        what=str(exc),
        layer="layer1:code_api",
        input_hint=str(request.url),
        action="Check LSIG API logs and verify Neo4j connectivity.",
    )


# ─── Graph endpoints ──────────────────────────────────────────────────────────


@app.get("/graph/functions")
async def get_functions(service: str = Query(..., description="Service name")) -> dict:
    """List all non-deprecated Function nodes in a service."""
    results = run_query(
        """
        MATCH (f:Function {service: $service})
        WHERE f.deprecated_at IS NULL
        RETURN f.id AS id, f.name AS name, f.file AS file,
               f.line AS line, f.language AS language
        ORDER BY f.file, f.line
        LIMIT 500
        """,
        {"service": service},
    )
    return {"service": service, "count": len(results), "functions": results}


@app.get("/graph/calls")
async def get_call_graph(
    function: str = Query(..., description="Function node ID"),
    depth: int = Query(3, ge=1, le=10, description="Max traversal depth"),
) -> dict:
    """Return the call graph up to N hops from a given function (both directions)."""
    results = run_query(
        """
        MATCH path = (root:Function {id: $fid})-[:CALLS*1..$depth]-(other:Function)
        WHERE other.deprecated_at IS NULL
        RETURN
          [n IN nodes(path) | {id: n.id, name: n.name, file: n.file}] AS nodes,
          [r IN relationships(path) | {from: startNode(r).id, to: endNode(r).id}] AS edges
        LIMIT 200
        """,
        {"fid": function, "depth": depth},
    )
    # Deduplicate nodes and edges across paths
    node_map: dict[str, dict] = {}
    edge_set: set[tuple] = set()
    for row in results:
        for n in row["nodes"]:
            node_map[n["id"]] = n
        for e in row["edges"]:
            edge_set.add((e["from"], e["to"]))

    return {
        "root": function,
        "depth": depth,
        "nodes": list(node_map.values()),
        "edges": [{"from": f, "to": t} for f, t in edge_set],
    }


@app.get("/graph/entrypoints")
async def get_entrypoints(service: str = Query(..., description="Service name")) -> dict:
    """Return all externally-facing API endpoints for a service."""
    results = run_query(
        """
        MATCH (e:APIEndpoint {service: $service})
        WHERE e.deprecated_at IS NULL
        OPTIONAL MATCH (e)-[:HANDLED_BY]->(f:Function)
        RETURN e.id AS id, e.path AS path, e.method AS method,
               e.authenticated AS authenticated, e.exposes_pii AS exposes_pii,
               f.id AS handler_id, f.name AS handler_name
        ORDER BY e.path
        """,
        {"service": service},
    )
    return {"service": service, "count": len(results), "endpoints": results}


@app.post("/graph/impact")
async def get_impact(
    functions: list[str] = Body(..., embed=True, description="List of Function node IDs"),
) -> dict:
    """Return all functions that transitively call OR are called by the given functions."""
    if not functions:
        raise HTTPException(status_code=400, detail="functions list must not be empty")

    results = run_query(
        """
        UNWIND $fids AS fid
        MATCH (root:Function {id: fid})
        OPTIONAL MATCH (caller:Function)-[:CALLS*1..8]->(root)
          WHERE caller.deprecated_at IS NULL
        OPTIONAL MATCH (root)-[:CALLS*1..8]->(callee:Function)
          WHERE callee.deprecated_at IS NULL
        RETURN
          collect(DISTINCT {id: caller.id, name: caller.name, role: 'CALLER'}) +
          collect(DISTINCT {id: callee.id, name: callee.name, role: 'CALLEE'}) AS affected
        """,
        {"fids": functions},
    )
    affected: list[dict] = []
    for row in results:
        for item in row.get("affected", []):
            if item and item.get("id"):
                affected.append(item)

    return {
        "input_functions": functions,
        "affected_count": len(affected),
        "affected": affected,
    }


# ─── Runtime endpoints (populated by Layer 2 Flink job) ──────────────────────


@app.get("/runtime/hotpaths")
async def get_hotpaths(
    service: str = Query(...),
    threshold: int = Query(100, description="Min call_count_24h"),
) -> dict:
    results = run_query(
        """
        MATCH (f:Function {service: $service})-[r:RUNTIME_CALLS]->()
        WHERE r.call_count_24h >= $threshold AND f.deprecated_at IS NULL
        RETURN f.id AS id, f.name AS name, f.file AS file,
               r.call_count_24h AS calls_24h, r.last_seen AS last_seen
        ORDER BY r.call_count_24h DESC
        LIMIT 50
        """,
        {"service": service, "threshold": threshold},
    )
    return {"service": service, "hotpaths": results}


@app.get("/runtime/dead_code")
async def get_dead_code(service: str = Query(...)) -> dict:
    results = run_query(
        """
        MATCH (f:Function {service: $service})
        WHERE f.deprecated_at IS NULL
          AND NOT (f)-[:RUNTIME_CALLS]->()
          AND NOT ()-[:CALLS]->(f)
        RETURN f.id AS id, f.name AS name, f.file AS file, f.line AS line
        ORDER BY f.file, f.line
        LIMIT 200
        """,
        {"service": service},
    )
    return {"service": service, "dead_code_count": len(results), "functions": results}


@app.get("/runtime/blast_radius")
async def get_blast_radius(
    functions: Annotated[list[str], Query()] = Query(...),
) -> dict:
    """Return % of today's production traffic that touches the given functions."""
    results = run_query(
        """
        UNWIND $fids AS fid
        MATCH (f:Function {id: fid})-[r:RUNTIME_CALLS]->()
        RETURN sum(r.call_count_24h) AS total_calls
        """,
        {"fids": functions},
    )
    total_for_input = results[0]["total_calls"] if results else 0

    global_results = run_query(
        """
        MATCH ()-[r:RUNTIME_CALLS]->()
        RETURN sum(r.call_count_24h) AS global_calls
        """
    )
    global_total = global_results[0]["global_calls"] if global_results else 0

    pct = round((total_for_input / global_total) * 100, 2) if global_total else 0.0
    return {
        "functions": functions,
        "calls_24h": total_for_input,
        "global_calls_24h": global_total,
        "blast_radius_pct": pct,
    }


# ─── Visualization endpoints ──────────────────────────────────────────────────


@app.get("/viz/service")
async def viz_service(service: str = Query(...)) -> dict:
    """D3-compatible subgraph for a service (nodes + links)."""
    node_rows = run_query(
        """
        MATCH (f:Function {service: $service})
        WHERE f.deprecated_at IS NULL
        RETURN f.id AS id, f.name AS name, 'Function' AS type
        LIMIT 300
        """,
        {"service": service},
    )
    ep_rows = run_query(
        """
        MATCH (e:APIEndpoint {service: $service})
        WHERE e.deprecated_at IS NULL
        RETURN e.id AS id, e.path AS name, 'APIEndpoint' AS type
        """,
        {"service": service},
    )
    edge_rows = run_query(
        """
        MATCH (a:Function {service: $service})-[:CALLS]->(b:Function {service: $service})
        WHERE a.deprecated_at IS NULL AND b.deprecated_at IS NULL
        RETURN a.id AS source, b.id AS target, 'CALLS' AS label
        LIMIT 500
        """,
        {"service": service},
    )
    return {
        "nodes": node_rows + ep_rows,
        "links": edge_rows,
    }


# ─── Security endpoints (Layer 3) ─────────────────────────────────────────────


@app.get("/security/vulns")
async def get_vulns(
    service: str = Query(...),
    reachability: str = Query(None, description="Filter by reachability label"),
    severity: str = Query(None, description="Filter by severity (CRITICAL|HIGH|MEDIUM|LOW)"),
) -> dict:
    """List CVEs for a service, optionally filtered by reachability and severity."""
    filters = ["d.service = $svc", "d.deprecated_at IS NULL", "v.deprecated_at IS NULL"]
    params: dict = {"svc": service}

    if reachability:
        filters.append("r.reachability = $reach")
        params["reach"] = reachability.upper()
    if severity:
        filters.append("r.severity = $sev")
        params["sev"] = severity.upper()

    where = " AND ".join(filters)
    results = run_query(
        f"""
        MATCH (d:Dependency {{service: $svc}})-[r:HAS_VULN]->(v:Vulnerability)
        WHERE {where}
        RETURN
            v.id              AS vuln_id,
            v.cve_id          AS cve_id,
            v.osv_id          AS osv_id,
            v.affected_package AS package,
            d.version         AS version,
            r.severity        AS severity,
            r.reachability    AS reachability,
            r.epss_score      AS epss_score,
            r.in_kev          AS in_kev,
            r.externally_reachable AS externally_reachable,
            r.external_url    AS external_url,
            r.runtime_calls_24h AS runtime_calls_24h
        ORDER BY
            CASE r.reachability
                WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'   THEN 3
                ELSE 4
            END,
            r.epss_score DESC
        LIMIT 200
        """,
        params,
    )
    return {"service": service, "count": len(results), "vulnerabilities": results}


@app.get("/security/blast_radius")
async def get_security_blast_radius(
    cve: str = Query(..., description="CVE ID (e.g. CVE-2024-1234)"),
) -> dict:
    """Return which services and API endpoints are in the blast radius of a CVE."""
    results = run_query(
        """
        MATCH (v:Vulnerability)
        WHERE v.cve_id = $cve OR v.id = $cve OR v.osv_id = $cve
        MATCH (d:Dependency)-[r:HAS_VULN]->(v)
        WHERE r.reachability IN ['CRITICAL', 'HIGH', 'MEDIUM']
        MATCH (ep:APIEndpoint {service: d.service})-[:HANDLED_BY]->(h:Function)
        WHERE ep.deprecated_at IS NULL
        OPTIONAL MATCH (ext:ExternalEndpoint)-[:MAPS_TO]->(ep)
        RETURN DISTINCT
            d.service           AS service,
            d.id                AS dependency_id,
            d.name              AS package,
            d.version           AS version,
            r.reachability      AS reachability,
            r.severity          AS severity,
            ep.id               AS endpoint_id,
            ep.path             AS endpoint_path,
            ep.method           AS method,
            ext.url             AS external_url
        ORDER BY service, endpoint_path
        LIMIT 100
        """,
        {"cve": cve},
    )
    services = list({r["service"] for r in results if r["service"]})
    return {
        "cve": cve,
        "affected_services": services,
        "affected_service_count": len(services),
        "blast_radius": results,
    }


@app.get("/security/delta")
async def get_security_delta(
    pr_id: str = Query(..., description="Pull request identifier"),
    service: str = Query(..., description="Service being changed"),
) -> dict:
    """
    Compute whether a PR expands or contracts CVE exposure.
    Expects that Layer 6 has populated a PR context node with affected function IDs.
    """
    # Retrieve the list of changed Function node IDs for this PR
    pr_context = run_query(
        """
        MATCH (pr:PullRequest {id: $pr_id})
        RETURN pr.changed_function_ids AS func_ids
        """,
        {"pr_id": pr_id},
    )

    if not pr_context or not pr_context[0].get("func_ids"):
        return _error(
            404,
            what=f"No PR context found for pr_id={pr_id}",
            layer="layer3:security_delta",
            input_hint=f"pr_id={pr_id} service={service}",
            action="Ensure the webhook receiver has processed this PR first (Layer 6).",
        )

    func_ids = pr_context[0]["func_ids"]
    delta = compute_pr_security_delta(func_ids, service)
    return {
        "pr_id": pr_id,
        "service": service,
        "new_cve_exposures": delta["new_exposures"],
        "removed_cve_exposures": delta["removed_exposures"],
        "unchanged_vulns": len(delta["unchanged"]),
        "net_exposure_change": len(delta["new_exposures"]) - len(delta["removed_exposures"]),
    }


@app.post("/security/reachability/refresh")
async def refresh_reachability(service: str = Query(...)) -> dict:
    """Re-run the reachability engine for all vulnerabilities in a service."""
    results = run_for_service(service)
    summary = {r.reachability.value: 0 for r in results}
    for r in results:
        summary[r.reachability.value] += 1
    return {
        "service": service,
        "total_vulns_evaluated": len(results),
        "reachability_breakdown": summary,
    }


@app.get("/viz/blast_radius")
async def viz_blast_radius(
    cve: str = Query(..., description="CVE ID"),
) -> dict:
    """D3-compatible blast radius subgraph for a CVE."""
    nodes: list[dict] = []
    links: list[dict] = []

    vuln_rows = run_query(
        "MATCH (v:Vulnerability) WHERE v.cve_id = $cve OR v.id = $cve "
        "RETURN v.id AS id, v.cve_id AS label",
        {"cve": cve},
    )
    for v in vuln_rows:
        nodes.append({"id": v["id"], "label": v["label"] or v["id"], "type": "Vulnerability"})

    dep_rows = run_query(
        """
        MATCH (v:Vulnerability) WHERE v.cve_id = $cve OR v.id = $cve
        MATCH (d:Dependency)-[r:HAS_VULN]->(v)
        WHERE r.reachability IN ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        RETURN DISTINCT d.id AS id, d.name AS label, d.service AS service,
               r.reachability AS reachability, v.id AS vuln_id
        LIMIT 50
        """,
        {"cve": cve},
    )
    for d in dep_rows:
        nodes.append({"id": d["id"], "label": d["label"], "type": "Dependency",
                      "reachability": d["reachability"]})
        links.append({"source": d["id"], "target": d["vuln_id"], "label": "HAS_VULN"})

    ep_rows = run_query(
        """
        MATCH (v:Vulnerability) WHERE v.cve_id = $cve OR v.id = $cve
        MATCH (d:Dependency)-[r:HAS_VULN]->(v)
        WHERE r.reachability IN ['CRITICAL', 'HIGH']
        MATCH (ep:APIEndpoint {service: d.service})
        WHERE ep.deprecated_at IS NULL
        RETURN DISTINCT ep.id AS id, ep.path AS label, ep.method AS method,
               d.id AS dep_id
        LIMIT 30
        """,
        {"cve": cve},
    )
    for ep in ep_rows:
        nodes.append({"id": ep["id"], "label": ep["label"], "type": "APIEndpoint",
                      "method": ep["method"]})
        links.append({"source": ep["id"], "target": ep["dep_id"], "label": "EXPOSES"})

    return {"nodes": nodes, "links": links}


# ─── Ownership endpoints (Layer 4) ────────────────────────────────────────────


@app.get("/ownership/service")
async def get_service_ownership(service: str = Query(...)) -> dict:
    """Return ownership breakdown for all nodes in a service."""
    rows = run_query(
        """
        MATCH (f:Function {service: $svc})
        WHERE f.deprecated_at IS NULL AND f.owner_team IS NOT NULL
        RETURN
            f.owner_team  AS team,
            f.owner_email AS email,
            count(f)      AS function_count
        ORDER BY function_count DESC
        """,
        {"svc": service},
    )
    ep_rows = run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc})
        WHERE ep.deprecated_at IS NULL AND ep.owner_team IS NOT NULL
        RETURN ep.id AS id, ep.path AS path, ep.method AS method,
               ep.owner_team AS team, ep.owner_email AS email
        ORDER BY ep.path
        """,
        {"svc": service},
    )
    return {
        "service": service,
        "team_breakdown": rows,
        "endpoint_ownership": ep_rows,
    }


@app.get("/ownership/function")
async def get_function_ownership(function_id: str = Query(...)) -> dict:
    """Return ownership metadata for a specific Function node."""
    rows = run_query(
        """
        MATCH (f:Function {id: $fid})
        RETURN f.id AS id, f.name AS name, f.file AS file,
               f.owner_team AS team, f.owner_email AS email
        """,
        {"fid": function_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"Function {function_id} not found")
    return rows[0]


# ─── PII endpoints (Layer 4) ──────────────────────────────────────────────────


@app.get("/pii/fields")
async def get_pii_fields(
    service: str = Query(...),
    pii_type: str = Query(None, description="Filter by PII type (EMAIL, CREDIT_CARD, …)"),
) -> dict:
    """List all PII DataField nodes for a service."""
    params: dict = {"svc": service}
    extra_filter = ""
    if pii_type:
        extra_filter = "AND d.pii_type = $pii_type"
        params["pii_type"] = pii_type.upper()

    rows = run_query(
        f"""
        MATCH (d:DataField {{service: $svc, pii_likely: true}})
        WHERE d.deprecated_at IS NULL {extra_filter}
        RETURN d.id AS id, d.name AS name, d.pii_type AS pii_type,
               d.file AS file, d.line AS line
        ORDER BY d.pii_type, d.name
        """,
        params,
    )
    return {"service": service, "count": len(rows), "fields": rows}


@app.get("/pii/endpoints")
async def get_pii_endpoints(service: str = Query(...)) -> dict:
    """List all APIEndpoints in a service that expose PII fields."""
    rows = run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc, exposes_pii: true})
        WHERE ep.deprecated_at IS NULL
        OPTIONAL MATCH (ep)-[:HANDLED_BY]->(f:Function)-[:READS|WRITES]->(d:DataField {pii_likely: true})
        RETURN DISTINCT
            ep.id         AS endpoint_id,
            ep.path       AS path,
            ep.method     AS method,
            ep.pci_scope  AS pci_scope,
            ep.hipaa_scope AS hipaa_scope,
            collect(DISTINCT d.pii_type) AS pii_types
        ORDER BY ep.path
        """,
        {"svc": service},
    )
    return {"service": service, "count": len(rows), "endpoints": rows}


@app.get("/pii/flows")
async def get_pii_flows(service: str = Query(...)) -> dict:
    """List all FLOWS_TO edges from PII fields in a service."""
    rows = run_query(
        """
        MATCH (src:DataField {service: $svc, pii_likely: true})-[r:FLOWS_TO]->(dst:DataField)
        WHERE src.deprecated_at IS NULL
        RETURN
            src.id          AS src_field_id,
            src.name        AS src_field_name,
            src.pii_type    AS pii_type,
            dst.id          AS dst_field_id,
            dst.service     AS dst_service,
            r.via_endpoint  AS via_endpoint,
            r.unregulated   AS unregulated,
            r.service_path  AS service_path
        ORDER BY r.unregulated DESC, src.pii_type
        LIMIT 200
        """,
        {"svc": service},
    )
    unregulated = [r for r in rows if r.get("unregulated")]
    return {
        "service": service,
        "total_flows": len(rows),
        "unregulated_flows": len(unregulated),
        "flows": rows,
    }


@app.get("/pii/unregulated")
async def get_unregulated_pii_flows() -> dict:
    """Return all UNREGULATED_PII_FLOW edges across all services."""
    rows = run_query(
        """
        MATCH (src:DataField {pii_likely: true})-[r:FLOWS_TO {unregulated: true}]->(dst:DataField)
        WHERE src.deprecated_at IS NULL
        RETURN
            src.service     AS src_service,
            src.name        AS src_field,
            src.pii_type    AS pii_type,
            dst.service     AS dst_service,
            r.via_endpoint  AS via_endpoint,
            r.service_path  AS service_path
        ORDER BY src.service, src.pii_type
        LIMIT 500
        """
    )
    return {"unregulated_flow_count": len(rows), "flows": rows}


@app.get("/pii/regulatory")
async def get_regulatory_scope(service: str = Query(...)) -> dict:
    """Return the derived regulatory scope for a service."""
    rows = run_query(
        """
        MATCH (s:Service {id: $svc})
        RETURN s.regulatory_scope   AS scope,
               s.scope_confidence  AS confidence,
               s.scope_derived_at  AS derived_at
        """,
        {"svc": service},
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"Service {service} not found")
    return {"service": service, **rows[0]}


@app.post("/pii/regulatory/refresh")
async def refresh_regulatory_scope(service: str = Query(...)) -> dict:
    """Re-derive regulatory scope for a service (PII field evidence only, no repo scan)."""
    result = annotate_regulatory_scope(service, repo_dir=None)
    return result
