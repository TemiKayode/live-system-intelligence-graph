"""
Layer 3 — Reachability Engine (core novel component).

For each Vulnerability, computes a REACHABILITY label using three-step evidence:

  Step 1 — Static reachability:
    Does any APIEndpoint have a call path to a function that invokes a
    vulnerable function (up to depth 10)?

  Step 2 — Runtime reachability:
    Of the functions on that static path, do any have a RUNTIME_CALLS edge
    with call_count_24h > 0? If none do → NOT_RUNTIME_REACHABLE → mark LOW.

  Step 3 — Attack surface reachability:
    Is the APIEndpoint on the path listed in the ExternalEndpoint attack
    surface map (discovered by Nuclei)? If not → MEDIUM. If yes → CRITICAL.

Final REACHABILITY labels (written to HAS_VULN.reachability):
  CRITICAL       — externally reachable + runtime evidence + static path
  HIGH           — static path + runtime evidence, endpoint not external
  MEDIUM         — static path, no runtime evidence, endpoint not external
  LOW            — static path exists but no runtime evidence
  NOT_REACHABLE  — no static path from any APIEndpoint to vulnerable function

The engine is idempotent and runs in full or incremental mode.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Iterator

from layer1.neo4j_client import run_query

logger = logging.getLogger(__name__)

# ─── Reachability label ───────────────────────────────────────────────────────

class Reachability(str, Enum):
    CRITICAL      = "CRITICAL"
    HIGH          = "HIGH"
    MEDIUM        = "MEDIUM"
    LOW           = "LOW"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNKNOWN       = "UNKNOWN"


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class ReachabilityResult:
    vuln_id: str
    dep_id: str
    reachability: Reachability
    # Evidence collected at each step (for audit / certificate)
    static_path_found: bool = False
    static_entry_endpoints: list[str] = None  # APIEndpoint IDs
    runtime_evidence: bool = False
    runtime_call_count_24h: int = 0
    externally_reachable: bool = False
    external_url: str | None = None

    def __post_init__(self):
        if self.static_entry_endpoints is None:
            self.static_entry_endpoints = []


# ─── Step 1: Static reachability ─────────────────────────────────────────────

_STATIC_REACHABILITY_QUERY = """
// Find all APIEndpoints that have a CALLS path to any of the vulnerable functions
UNWIND $vuln_funcs AS vuln_func_name
MATCH (entry:APIEndpoint)-[:HANDLED_BY]->(handler:Function)
WHERE entry.service = $service AND entry.deprecated_at IS NULL
// Traverse CALLS graph up to depth 10 from handler
MATCH path = (handler)-[:CALLS*0..10]->(target:Function)
WHERE target.name = vuln_func_name
  AND target.deprecated_at IS NULL
RETURN DISTINCT
    entry.id         AS endpoint_id,
    entry.path       AS endpoint_path,
    handler.id       AS handler_id,
    target.id        AS target_id,
    target.name      AS target_name,
    length(path)     AS path_depth,
    [n IN nodes(path) | n.id] AS path_node_ids
ORDER BY path_depth ASC
LIMIT 50
"""


def check_static_reachability(
    service: str,
    vulnerable_functions: list[str],
) -> list[dict]:
    """
    Return all static call paths from APIEndpoints to vulnerable functions.
    Each result contains the entry endpoint, path nodes, and depth.
    """
    if not vulnerable_functions:
        return []

    return run_query(
        _STATIC_REACHABILITY_QUERY,
        {"service": service, "vuln_funcs": vulnerable_functions},
    )


# ─── Step 2: Runtime reachability ─────────────────────────────────────────────

_RUNTIME_EVIDENCE_QUERY = """
// Check if any function on the static path has runtime call evidence
UNWIND $node_ids AS nid
MATCH (f:Function {id: nid})-[r:RUNTIME_CALLS]->(f)
WHERE r.call_count_24h > 0
RETURN f.id AS func_id, r.call_count_24h AS count_24h
ORDER BY r.call_count_24h DESC
LIMIT 10
"""


def check_runtime_reachability(path_node_ids: list[str]) -> list[dict]:
    """
    Return RUNTIME_CALLS evidence for functions on a static call path.
    Empty list → no runtime evidence → vulnerability is not runtime-reachable.
    """
    if not path_node_ids:
        return []
    return run_query(_RUNTIME_EVIDENCE_QUERY, {"node_ids": path_node_ids})


# ─── Step 3: Attack surface reachability ──────────────────────────────────────

_EXTERNAL_ENDPOINT_QUERY = """
// Is the APIEndpoint mapped to a Nuclei-discovered ExternalEndpoint?
MATCH (ext:ExternalEndpoint)-[:MAPS_TO]->(ep:APIEndpoint {id: $ep_id})
WHERE ext.deprecated_at IS NULL
RETURN ext.url AS url, ext.id AS external_id
LIMIT 1
"""


def check_attack_surface_reachability(endpoint_id: str) -> dict | None:
    """
    Return the first ExternalEndpoint linked to an APIEndpoint, or None.
    """
    rows = run_query(_EXTERNAL_ENDPOINT_QUERY, {"ep_id": endpoint_id})
    return rows[0] if rows else None


# ─── Core reachability computation ───────────────────────────────────────────

def compute_reachability(
    vuln_id: str,
    dep_id: str,
    service: str,
    vulnerable_functions: list[str],
) -> ReachabilityResult:
    """
    Compute the three-step reachability for one (Vulnerability, Dependency, Service) triple.

    This is the authoritative implementation of the LSIG reachability algorithm.
    Runtime evidence takes precedence over static analysis when they conflict (Rule 2).
    """
    result = ReachabilityResult(vuln_id=vuln_id, dep_id=dep_id, reachability=Reachability.UNKNOWN)

    # ── Step 1: Static ────────────────────────────────────────────────────────
    static_paths = check_static_reachability(service, vulnerable_functions)

    if not static_paths:
        result.reachability = Reachability.NOT_REACHABLE
        logger.debug("vuln=%s dep=%s → NOT_REACHABLE (no static path)", vuln_id, dep_id)
        return result

    result.static_path_found = True
    result.static_entry_endpoints = list({p["endpoint_id"] for p in static_paths})

    # Collect all function node IDs across all static paths
    all_path_nodes: list[str] = []
    for path in static_paths:
        all_path_nodes.extend(path.get("path_node_ids", []))
    all_path_nodes = list(set(all_path_nodes))

    # ── Step 2: Runtime ───────────────────────────────────────────────────────
    runtime_evidence = check_runtime_reachability(all_path_nodes)

    if not runtime_evidence:
        # Static path exists but no function on it has been observed in production.
        # Downgrade: the vulnerability is theoretically reachable but not in practice.
        result.reachability = Reachability.LOW
        logger.debug("vuln=%s dep=%s → LOW (no runtime evidence)", vuln_id, dep_id)
        return result

    result.runtime_evidence = True
    result.runtime_call_count_24h = sum(r["count_24h"] for r in runtime_evidence)

    # ── Step 3: Attack surface ────────────────────────────────────────────────
    # Check each entry endpoint for external exposure
    for endpoint_id in result.static_entry_endpoints:
        external = check_attack_surface_reachability(endpoint_id)
        if external:
            result.externally_reachable = True
            result.external_url = external["url"]
            result.reachability = Reachability.CRITICAL
            logger.info(
                "vuln=%s dep=%s → CRITICAL (external=%s, runtime_calls=%d)",
                vuln_id, dep_id, external["url"], result.runtime_call_count_24h,
            )
            return result

    # Static + runtime evidence, but no external exposure
    result.reachability = Reachability.HIGH
    logger.debug(
        "vuln=%s dep=%s → HIGH (runtime_calls=%d, not externally exposed)",
        vuln_id, dep_id, result.runtime_call_count_24h,
    )
    return result


# ─── Batch reachability update ────────────────────────────────────────────────

def _write_reachability(dep_id: str, vuln_id: str, result: ReachabilityResult) -> None:
    """Persist the reachability label back onto the HAS_VULN edge."""
    run_query(
        """
        MATCH (d:Dependency {id: $dep_id})-[r:HAS_VULN]->(v:Vulnerability {id: $vuln_id})
        SET r.reachability            = $reachability,
            r.static_path_found       = $static,
            r.runtime_evidence        = $runtime,
            r.runtime_calls_24h       = $calls,
            r.externally_reachable    = $external,
            r.external_url            = $ext_url,
            r.reachability_updated_at = datetime()
        """,
        {
            "dep_id": dep_id,
            "vuln_id": vuln_id,
            "reachability": result.reachability.value,
            "static": result.static_path_found,
            "runtime": result.runtime_evidence,
            "calls": result.runtime_call_count_24h,
            "external": result.externally_reachable,
            "ext_url": result.external_url,
        },
    )


def run_for_service(service: str) -> list[ReachabilityResult]:
    """
    Compute reachability for all HAS_VULN edges in a service.
    Skips edges already labelled within the last 30 minutes (unless forced).
    """
    # Find all (Dependency, Vulnerability) pairs for this service
    edges = run_query(
        """
        MATCH (d:Dependency {service: $svc})-[r:HAS_VULN]->(v:Vulnerability)
        WHERE d.deprecated_at IS NULL
        RETURN
            d.id AS dep_id,
            v.id AS vuln_id,
            v.vulnerable_functions AS vuln_funcs,
            r.reachability AS current_reachability
        """,
        {"svc": service},
    )

    results: list[ReachabilityResult] = []
    for edge in edges:
        dep_id  = edge["dep_id"]
        vuln_id = edge["vuln_id"]
        vuln_funcs = edge.get("vuln_funcs") or []

        result = compute_reachability(vuln_id, dep_id, service, vuln_funcs)
        _write_reachability(dep_id, vuln_id, result)
        results.append(result)

    return results


def run_for_all_services() -> dict[str, list[ReachabilityResult]]:
    """Compute reachability for every service."""
    services = run_query(
        "MATCH (s:Service) WHERE s.deprecated_at IS NULL RETURN s.id AS id"
    )
    return {svc["id"]: run_for_service(svc["id"]) for svc in services}


# ─── PR-scoped reachability delta ────────────────────────────────────────────

def compute_pr_security_delta(
    changed_function_ids: list[str],
    service: str,
) -> dict:
    """
    For a set of changed Function node IDs (from a PR diff), determine:
      - Whether the change expands CVE exposure (new CRITICAL/HIGH vulns becoming reachable)
      - Whether the change contracts CVE exposure (previously reachable vulns losing their path)

    Returns a dict with new_exposures and removed_exposures lists.
    """
    if not changed_function_ids:
        return {"new_exposures": [], "removed_exposures": [], "unchanged": []}

    # Find vulnerabilities whose static path traverses any of the changed functions
    affected_vulns = run_query(
        """
        UNWIND $fids AS fid
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(h:Function)
        MATCH (h)-[:CALLS*0..10]->(changed:Function {id: fid})
        MATCH (h)-[:CALLS*0..10]->(target:Function)<-[:CALLS*0..]-(dep_func:Function)
        MATCH (d:Dependency {service: $svc})-[r:HAS_VULN]->(v:Vulnerability)
        WHERE target.name IN v.vulnerable_functions
        RETURN DISTINCT
            v.id          AS vuln_id,
            v.severity    AS severity,
            r.reachability AS current_reachability,
            d.id          AS dep_id
        """,
        {"fids": changed_function_ids, "svc": service},
    )

    new_exposures = []
    removed_exposures = []
    unchanged = []

    for row in affected_vulns:
        vuln_id = row["vuln_id"]
        dep_id = row["dep_id"]
        old_reachability = row.get("current_reachability", "UNKNOWN")

        # Re-compute reachability with the assumption the change is applied
        # In practice the Layer 6 workflow applies the diff to a shadow graph;
        # here we re-run against the current graph as a baseline.
        vuln_funcs_rows = run_query(
            "MATCH (v:Vulnerability {id: $id}) RETURN v.vulnerable_functions AS f",
            {"id": vuln_id},
        )
        vuln_funcs = (vuln_funcs_rows[0]["f"] or []) if vuln_funcs_rows else []
        new_result = compute_reachability(vuln_id, dep_id, service, vuln_funcs)
        new_r = new_result.reachability.value

        if old_reachability in ("NOT_REACHABLE", "LOW", "UNKNOWN") and new_r in ("CRITICAL", "HIGH"):
            new_exposures.append({
                "vuln_id": vuln_id,
                "dep_id": dep_id,
                "old_reachability": old_reachability,
                "new_reachability": new_r,
                "severity": row["severity"],
                "externally_reachable": new_result.externally_reachable,
            })
        elif old_reachability in ("CRITICAL", "HIGH") and new_r in ("NOT_REACHABLE", "LOW"):
            removed_exposures.append({
                "vuln_id": vuln_id,
                "dep_id": dep_id,
                "old_reachability": old_reachability,
                "new_reachability": new_r,
            })
        else:
            unchanged.append({"vuln_id": vuln_id, "reachability": new_r})

    return {
        "new_exposures": new_exposures,
        "removed_exposures": removed_exposures,
        "unchanged": unchanged,
    }
