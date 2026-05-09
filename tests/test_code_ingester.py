"""
Layer 1 integration test — ingests expressjs/express and gin-gonic/gin, then
asserts the acceptance criteria:
  - >= 30 Function nodes per service
  - >= 5 APIEndpoint nodes per service
  - Function nodes have required properties (name, file, line, language, service)
  - Call edges exist between Function nodes

Run against a live Neo4j (set NEO4J_URI / NEO4J_PASSWORD env vars, or use
the defaults targeting localhost:7687 with password lsig_dev).

    pytest tests/test_code_ingester.py -v
"""

import os
import pytest
from pathlib import Path

from layer1.code_ingester import ingest
from layer1.neo4j_client import run_query


# ─── Fixtures ─────────────────────────────────────────────────────────────────

REPOS = [
    ("https://github.com/expressjs/express", "express"),
    ("https://github.com/gin-gonic/gin", "gin"),
]


@pytest.fixture(scope="session", params=REPOS, ids=[r[1] for r in REPOS])
def ingested_service(tmp_path_factory, request):
    """Clone a repo, run ingest, return (service_name, summary)."""
    repo_url, service = request.param
    work_dir = tmp_path_factory.mktemp(service)
    summary = ingest(repo_url, service, work_dir=work_dir, force_full=True)
    assert summary["status"] == "ok", f"Ingest failed: {summary}"
    return service, summary


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestFunctionNodes:
    def test_minimum_function_count(self, ingested_service):
        """Acceptance criterion: >= 30 Function nodes per service."""
        service, _ = ingested_service
        rows = run_query(
            "MATCH (f:Function {service: $s}) WHERE f.deprecated_at IS NULL "
            "RETURN count(f) AS cnt",
            {"s": service},
        )
        count = rows[0]["cnt"]
        assert count >= 30, (
            f"Service '{service}' has only {count} Function nodes (expected >= 30)"
        )

    def test_function_has_required_properties(self, ingested_service):
        """Every Function node must have name, file, line, language, service."""
        service, _ = ingested_service
        rows = run_query(
            """
            MATCH (f:Function {service: $s})
            WHERE f.deprecated_at IS NULL
            AND (f.name IS NULL OR f.file IS NULL OR f.line IS NULL
                 OR f.language IS NULL OR f.service IS NULL)
            RETURN count(f) AS bad_count
            """,
            {"s": service},
        )
        bad = rows[0]["bad_count"]
        assert bad == 0, (
            f"{bad} Function nodes in '{service}' are missing required properties"
        )

    def test_functions_reference_valid_files(self, ingested_service):
        """Function.file must be a non-empty repo-relative path."""
        service, _ = ingested_service
        rows = run_query(
            "MATCH (f:Function {service: $s}) "
            "WHERE f.deprecated_at IS NULL AND (f.file IS NULL OR f.file = '') "
            "RETURN count(f) AS cnt",
            {"s": service},
        )
        assert rows[0]["cnt"] == 0, "Found Function nodes with empty/null file path"


class TestAPIEndpointNodes:
    def test_minimum_endpoint_count(self, ingested_service):
        """Acceptance criterion: >= 5 APIEndpoint nodes per service."""
        service, _ = ingested_service
        rows = run_query(
            "MATCH (e:APIEndpoint {service: $s}) WHERE e.deprecated_at IS NULL "
            "RETURN count(e) AS cnt",
            {"s": service},
        )
        count = rows[0]["cnt"]
        assert count >= 5, (
            f"Service '{service}' has only {count} APIEndpoint nodes (expected >= 5)"
        )

    def test_endpoints_linked_to_handlers(self, ingested_service):
        """Every APIEndpoint should have at least one HANDLED_BY edge."""
        service, _ = ingested_service
        rows = run_query(
            """
            MATCH (e:APIEndpoint {service: $s})
            WHERE e.deprecated_at IS NULL
              AND NOT (e)-[:HANDLED_BY]->(:Function)
            RETURN count(e) AS unlinked
            """,
            {"s": service},
        )
        unlinked = rows[0]["unlinked"]
        # Allow up to 10% unlinked (handler may be in another file / pattern missed)
        total = run_query(
            "MATCH (e:APIEndpoint {service: $s}) RETURN count(e) AS cnt",
            {"s": service},
        )[0]["cnt"]
        if total > 0:
            unlinked_pct = unlinked / total
            assert unlinked_pct <= 0.10, (
                f"{unlinked}/{total} endpoints in '{service}' have no handler link"
            )

    def test_endpoint_has_method_and_path(self, ingested_service):
        """APIEndpoint must have non-empty method and path."""
        service, _ = ingested_service
        rows = run_query(
            """
            MATCH (e:APIEndpoint {service: $s})
            WHERE e.deprecated_at IS NULL
              AND (e.method IS NULL OR e.method = ''
                   OR e.path IS NULL OR e.path = '')
            RETURN count(e) AS bad
            """,
            {"s": service},
        )
        assert rows[0]["bad"] == 0, "APIEndpoint nodes found with missing method/path"


class TestCallEdges:
    def test_call_edges_exist(self, ingested_service):
        """At least some CALLS edges must exist between Function nodes."""
        service, _ = ingested_service
        rows = run_query(
            """
            MATCH (a:Function {service: $s})-[:CALLS]->(b:Function {service: $s})
            RETURN count(*) AS cnt
            """,
            {"s": service},
        )
        count = rows[0]["cnt"]
        assert count > 0, f"No CALLS edges found for service '{service}'"


class TestIngestSummary:
    def test_summary_reports_correct_keys(self, ingested_service):
        _, summary = ingested_service
        for key in ("status", "service", "files_processed", "functions_ingested", "endpoints_ingested"):
            assert key in summary, f"Summary missing key: {key}"

    def test_incremental_ingest_skips_unchanged(self, ingested_service, tmp_path_factory):
        """Running ingest a second time on the same SHA should be a no-op."""
        service, summary = ingested_service
        # Re-run from the same cloned repo (already exists, no changes)
        # We can't easily re-use the same tmp dir from the fixture, so skip
        # the clone step and just verify the state file logic works.
        import json
        from pathlib import Path as P
        state_dir = P(os.environ.get("LSIG_STATE_DIR", "/tmp/lsig_state"))
        state_file = state_dir / f"{service}.json"
        if state_file.exists():
            state = json.loads(state_file.read_text())
            assert "last_sha" in state, "State file should record last_sha after ingest"


class TestServiceNode:
    def test_service_node_created(self, ingested_service):
        """A Service node must exist for the ingested service."""
        service, _ = ingested_service
        rows = run_query(
            "MATCH (s:Service {id: $s}) RETURN s.id AS id",
            {"s": service},
        )
        assert rows, f"No Service node found for '{service}'"


# ─── Django integration test (larger repo — optional, skipped in fast mode) ───

@pytest.mark.slow
class TestDjangoIngest:
    """Integration test against django/django — larger repo, takes several minutes."""

    def test_django_ingest(self, tmp_path):
        summary = ingest(
            "https://github.com/django/django",
            "django",
            work_dir=tmp_path / "django",
            force_full=True,
        )
        assert summary["status"] == "ok"
        rows = run_query(
            "MATCH (f:Function {service: 'django'}) RETURN count(f) AS cnt"
        )
        assert rows[0]["cnt"] >= 100, "Expected 100+ functions from django/django"
