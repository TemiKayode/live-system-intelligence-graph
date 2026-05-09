"""
Layer 4 — Taint Flow Tracker.

Traces PII fields from source to sink across service boundaries using two
complementary strategies:

  Strategy A — CodeQL (when available):
    Runs CodeQL data-flow queries against each service repo.
    Produces precise interprocedural taint paths.

  Strategy B — Graph-walk heuristics (always available):
    Traverses the Neo4j code graph following READS/WRITES/CALLS/HANDLED_BY
    edges to find paths from PII DataFields to external APIEndpoints or
    cross-service calls.

Creates FLOWS_TO edges:
    (DataField)-[:FLOWS_TO {via_endpoint, service_path, regulated: bool}]->(DataField)

Flags flows where the destination service is missing a regulatory_scope annotation
as UNREGULATED_PII_FLOW on the relationship.

Usage:
    python -m layer4.taint_tracker --service myapp
    python -m layer4.taint_tracker --all
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from layer1.neo4j_client import run_query, upsert_node

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── CodeQL runner ────────────────────────────────────────────────────────────

_CODEQL_PII_QUERY_PYTHON = """
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * PII taint source: any attribute read whose name matches a PII pattern.
 */
class PiiSource extends DataFlow::Node {
  PiiSource() {
    exists(Attribute a |
      this.asExpr() = a and
      a.getName().regexpMatch(
        ".*(email|ssn|phone|credit_card|password|dob|passport|address).*"
      )
    )
  }
}

/**
 * PII taint sink: HTTP response body or cross-service call.
 */
class PiiSink extends DataFlow::Node {
  PiiSink() {
    exists(Call c |
      this.asExpr() = c.getAnArg() and
      (
        c.getFunc().(Attribute).getName() in ["json", "Response", "jsonify", "send"] or
        c.getFunc().(Attribute).getName() = "request"
      )
    )
  }
}

class PiiTaintConfig extends TaintTracking::Configuration {
  PiiTaintConfig() { this = "PiiTaintConfig" }
  override predicate isSource(DataFlow::Node src) { src instanceof PiiSource }
  override predicate isSink(DataFlow::Node sink) { sink instanceof PiiSink }
}

from PiiTaintConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select
  src.getNode().getLocation().getFile().getRelativePath() as src_file,
  src.getNode().getLocation().getStartLine() as src_line,
  sink.getNode().getLocation().getFile().getRelativePath() as sink_file,
  sink.getNode().getLocation().getStartLine() as sink_line,
  src.getNode().toString() as src_expr,
  sink.getNode().toString() as sink_expr
"""


def _codeql_available() -> bool:
    try:
        subprocess.run(["codeql", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _run_codeql_python(repo_dir: Path, output_path: Path) -> list[dict]:
    """Run CodeQL Python PII taint query. Returns list of flow records."""
    if not _codeql_available():
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "codeql-db"
        query_path = Path(tmpdir) / "pii_taint.ql"
        query_path.write_text(_CODEQL_PII_QUERY_PYTHON)

        # Create CodeQL database
        create_result = subprocess.run(
            ["codeql", "database", "create", str(db_path),
             "--language=python", f"--source-root={repo_dir}",
             "--overwrite"],
            capture_output=True, text=True, timeout=600,
        )
        if create_result.returncode != 0:
            logger.warning("CodeQL database creation failed: %s", create_result.stderr[:300])
            return []

        # Run query
        results_path = Path(tmpdir) / "results.bqrs"
        run_result = subprocess.run(
            ["codeql", "query", "run", str(query_path),
             f"--database={db_path}",
             f"--output={results_path}"],
            capture_output=True, text=True, timeout=300,
        )
        if run_result.returncode != 0:
            logger.warning("CodeQL query failed: %s", run_result.stderr[:300])
            return []

        # Decode results to CSV
        csv_path = Path(tmpdir) / "results.csv"
        subprocess.run(
            ["codeql", "bqrs", "decode", "--format=csv",
             f"--output={csv_path}", str(results_path)],
            capture_output=True, check=True,
        )

        flows = []
        for line in csv_path.read_text().splitlines()[1:]:  # skip header
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 6:
                flows.append({
                    "src_file": parts[0], "src_line": int(parts[1] or 0),
                    "sink_file": parts[2], "sink_line": int(parts[3] or 0),
                    "src_expr": parts[4], "sink_expr": parts[5],
                })
        return flows


# ─── Graph-walk heuristic taint analysis (Strategy B) ────────────────────────

def _find_pii_flows_via_graph(service: str) -> list[dict]:
    """
    Walk the Neo4j code graph to find PII DataFields that flow through
    APIEndpoints (same service) or to external function calls (cross-service).

    Returns list of flow dicts.
    """
    # Find all PII fields in this service and trace them to their endpoint
    rows = run_query(
        """
        // For each PII field, find the APIEndpoints that transitively read/write it
        MATCH (d:DataField {service: $svc, pii_likely: true})
        MATCH (f:Function)-[:READS|WRITES]->(d)
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(h:Function)
        MATCH path = (h)-[:CALLS*0..8]->(f)
        WHERE ep.deprecated_at IS NULL AND f.deprecated_at IS NULL
        RETURN DISTINCT
            d.id        AS src_field_id,
            d.name      AS src_field_name,
            d.pii_type  AS pii_type,
            ep.id       AS endpoint_id,
            ep.path     AS endpoint_path,
            ep.service  AS src_service,
            length(path) AS path_depth
        ORDER BY path_depth ASC
        LIMIT 200
        """,
        {"svc": service},
    )
    return rows


def _find_cross_service_calls(service: str) -> list[dict]:
    """
    Detect potential cross-service PII flows by looking for functions in
    service A that call HTTP client methods (requests.get, axios, http.Get, etc.)
    while being on the read path from a PII field.
    """
    http_client_patterns = [
        "requests.get", "requests.post", "requests.put", "requests.patch",
        "axios", "fetch", "http.Get", "http.Post", "urllib", "httpx",
        "RestTemplate", "WebClient", "Net::HTTP",
    ]

    # Look for functions that are called on a PII path AND call HTTP client methods
    rows = run_query(
        """
        MATCH (d:DataField {service: $svc, pii_likely: true})
        MATCH (reader:Function)-[:READS]->(d)
        MATCH (caller:Function)-[:CALLS*0..5]->(reader)
        MATCH (caller)-[:CALLS]->(http_fn:Function)
        WHERE http_fn.service = $svc
          AND any(pat IN $patterns WHERE http_fn.name CONTAINS pat)
        RETURN DISTINCT
            d.id            AS src_field_id,
            d.name          AS src_field_name,
            d.pii_type      AS pii_type,
            caller.id       AS caller_id,
            caller.name     AS caller_name,
            http_fn.name    AS http_call,
            $svc            AS src_service
        LIMIT 100
        """,
        {"svc": service, "patterns": http_client_patterns},
    )
    return rows


# ─── FLOWS_TO edge creation ───────────────────────────────────────────────────

@dataclass
class TaintFlow:
    src_field_id: str
    dst_field_id: str | None    # may be None for outbound-only flows
    via_endpoint: str           # APIEndpoint ID or function name
    src_service: str
    dst_service: str | None
    regulated: bool
    unregulated: bool


def _upsert_flows_to(flow: TaintFlow) -> None:
    if not flow.dst_field_id:
        return  # can't create edge without destination node
    run_query(
        """
        MATCH (src:DataField {id: $src})
        MATCH (dst:DataField {id: $dst})
        MERGE (src)-[r:FLOWS_TO]->(dst)
        SET r.via_endpoint   = $via,
            r.service_path   = $svc_path,
            r.regulated      = $regulated,
            r.unregulated    = $unregulated,
            r.detected_at    = datetime()
        """,
        {
            "src": flow.src_field_id,
            "dst": flow.dst_field_id,
            "via": flow.via_endpoint,
            "svc_path": f"{flow.src_service}→{flow.dst_service or 'external'}",
            "regulated": flow.regulated,
            "unregulated": flow.unregulated,
        },
    )


def _flag_unregulated_pii_flows(service: str) -> int:
    """
    Find FLOWS_TO edges where the destination service has no regulatory_scope
    annotation. Mark them as UNREGULATED_PII_FLOW. Returns count.
    """
    result = run_query(
        """
        MATCH (src:DataField {service: $svc})-[r:FLOWS_TO]->(dst:DataField)
        WHERE src.pii_likely = true
        MATCH (dst_svc:Service {id: dst.service})
        WHERE dst_svc.regulatory_scope IS NULL
           OR size(dst_svc.regulatory_scope) = 0
        SET r.unregulated = true
        RETURN count(r) AS cnt
        """,
        {"svc": service},
    )
    count = result[0]["cnt"] if result else 0
    if count:
        logger.warning(
            "Found %d UNREGULATED_PII_FLOW edges from service=%s", count, service
        )
    return count


def _service_is_regulated(dst_service: str) -> bool:
    rows = run_query(
        "MATCH (s:Service {id: $id}) RETURN s.regulatory_scope AS scope",
        {"id": dst_service},
    )
    if not rows:
        return False
    scope = rows[0].get("scope") or []
    return bool(scope)


# ─── Cross-service field matching ─────────────────────────────────────────────

def _find_matching_field_in_service(field_name: str, dst_service: str) -> str | None:
    """Look for a DataField with the same name in the destination service."""
    rows = run_query(
        """
        MATCH (d:DataField {service: $svc})
        WHERE d.name = $name AND d.deprecated_at IS NULL
        RETURN d.id AS id LIMIT 1
        """,
        {"svc": dst_service, "name": field_name},
    )
    return rows[0]["id"] if rows else None


def _infer_destination_service(endpoint_path: str, current_service: str) -> str | None:
    """
    Try to find another service whose APIEndpoints match the given path.
    Used when we detect a cross-service HTTP call.
    """
    rows = run_query(
        """
        MATCH (ep:APIEndpoint)
        WHERE ep.path = $path AND ep.service <> $svc AND ep.deprecated_at IS NULL
        RETURN ep.service AS svc LIMIT 1
        """,
        {"path": endpoint_path, "svc": current_service},
    )
    return rows[0]["svc"] if rows else None


# ─── Main pipeline ────────────────────────────────────────────────────────────

def analyse(service: str, repo_dir: str | Path | None = None) -> dict:
    """
    Run full taint analysis for a service.
    CodeQL is attempted first; graph-walk heuristics always run.

    Returns summary dict.
    """
    flows_created = 0
    unregulated = 0
    codeql_flows = 0

    # Strategy A: CodeQL (if available and repo_dir provided)
    if repo_dir and _codeql_available():
        repo = Path(repo_dir)
        with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
            raw_flows = _run_codeql_python(repo, Path(tmp.name))
        codeql_flows = len(raw_flows)
        for flow_data in raw_flows:
            src_name = flow_data.get("src_expr", "").split(".")[-1]
            dst_name = flow_data.get("sink_expr", "").split(".")[-1]
            src_id = f"{service}:{src_name}"
            dst_id = f"{service}:{dst_name}"
            flow = TaintFlow(
                src_field_id=src_id, dst_field_id=dst_id,
                via_endpoint=flow_data.get("sink_file", ""),
                src_service=service, dst_service=service,
                regulated=_service_is_regulated(service),
                unregulated=False,
            )
            _upsert_flows_to(flow)
            flows_created += 1

    # Strategy B: Graph-walk
    intra_flows = _find_pii_flows_via_graph(service)
    for row in intra_flows:
        src_field_id = row["src_field_id"]
        # For intra-service flows, create a self-loop to mark the field as endpoint-exposed
        flow = TaintFlow(
            src_field_id=src_field_id,
            dst_field_id=src_field_id,  # same field, marks it as endpoint-reachable
            via_endpoint=row.get("endpoint_id", ""),
            src_service=service,
            dst_service=service,
            regulated=_service_is_regulated(service),
            unregulated=False,
        )
        _upsert_flows_to(flow)
        flows_created += 1

    # Cross-service call detection
    cross_service = _find_cross_service_calls(service)
    for row in cross_service:
        src_field_id = row["src_field_id"]
        http_call = row.get("http_call", "")
        # Can't reliably determine destination without URL analysis; mark for investigation
        flow = TaintFlow(
            src_field_id=src_field_id,
            dst_field_id=None,    # unknown destination
            via_endpoint=http_call,
            src_service=service,
            dst_service=None,
            regulated=False,
            unregulated=True,
        )
        # Without a destination field ID we can't create a FLOWS_TO edge,
        # but we flag the source endpoint
        run_query(
            """
            MATCH (d:DataField {id: $fid})
            SET d.potential_cross_service_leak = true
            """,
            {"fid": src_field_id},
        )

    # Flag unregulated flows
    unregulated = _flag_unregulated_pii_flows(service)

    summary = {
        "status": "ok",
        "service": service,
        "codeql_flows": codeql_flows,
        "graph_flows_created": flows_created,
        "unregulated_pii_flows": unregulated,
    }
    logger.info("Taint analysis complete: %s", summary)
    return summary


def analyse_all_services() -> list[dict]:
    services = run_query(
        "MATCH (s:Service) WHERE s.deprecated_at IS NULL RETURN s.id AS id"
    )
    return [analyse(svc["id"]) for svc in services]


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="LSIG Layer 4 — Taint Tracker")
    parser.add_argument("--service", help="Service to analyse")
    parser.add_argument("--repo", help="Repo path (enables CodeQL)")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if args.all:
        print(json.dumps(analyse_all_services(), indent=2))
    elif args.service:
        print(json.dumps(analyse(args.service, args.repo), indent=2))
    else:
        parser.error("Provide --service or --all")
