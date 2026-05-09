"""
Layer 5 integration tests — Graph Store and Query Layer.

Acceptance criteria:
  - NL→Cypher: at least 5 natural-language queries produce valid Cypher and non-empty results
  - Prompt caching: second call for same schema has cache_read_input_tokens > 0
  - Weaviate semantic search: "auth" query returns Function nodes with certainty ≥ 0.5
  - VictoriaMetrics write+query round-trip succeeds
  - validate_cypher blocks all write operations
  - service_summary endpoint returns all 4 layer sections

Mocking strategy:
  - Claude API: mocked at anthropic.Anthropic level (no real API calls)
  - Neo4j: uses run_query mock returning fixture data
  - Weaviate: mocked client
  - VictoriaMetrics: mocked HTTP layer
"""

from __future__ import annotations

import json
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest


# ─── Fixtures ─────────────────────────────────────────────────────────────────

MOCK_FUNCTIONS = [
    {"id": "fn:auth:validate_token", "name": "validate_token", "file": "auth/jwt.py",
     "service": "auth", "language": "python", "owner_team": "@myorg/auth"},
    {"id": "fn:auth:refresh_token", "name": "refresh_token", "file": "auth/jwt.py",
     "service": "auth", "language": "python", "owner_team": "@myorg/auth"},
    {"id": "fn:payments:charge_card", "name": "charge_card", "file": "payments/stripe.py",
     "service": "payments", "language": "python", "owner_team": "@myorg/payments"},
]

MOCK_VULNS = [
    {"id": "vuln:CVE-2023-1234", "cve_id": "CVE-2023-1234", "severity": "CRITICAL",
     "affected_package": "requests", "epss_score": 0.85, "in_kev": True},
]

MOCK_ENDPOINTS = [
    {"id": "ep:auth:/login", "path": "/login", "method": "POST", "service": "auth",
     "authenticated": False, "exposes_pii": True},
]


def _make_claude_response(text: str, cache_read: int = 0) -> MagicMock:
    resp = MagicMock()
    resp.content = [MagicMock(text=text)]
    resp.usage = MagicMock()
    resp.usage.cache_read_input_tokens = cache_read
    resp.usage.input_tokens = 500
    return resp


# ─── validate_cypher tests ─────────────────────────────────────────────────────

class TestValidateCypher:

    def setup_method(self):
        from layer5.nl_to_cypher import validate_cypher
        self.validate = validate_cypher

    @pytest.mark.parametrize("query,should_pass", [
        ("MATCH (f:Function) WHERE f.deprecated_at IS NULL RETURN f LIMIT 50", True),
        ("MATCH (v:Vulnerability {severity: 'CRITICAL'}) RETURN v.cve_id", True),
        ("CREATE (n:Backdoor) RETURN n", False),
        ("MERGE (n:Node {id: 'x'}) SET n.bad = true RETURN n", False),
        ("MATCH (n) DELETE n", False),
        ("DETACH DELETE (n)", False),
        ("MATCH (n) REMOVE n.prop", False),
        ("LOAD CSV FROM 'http://evil.com' AS row", False),
        ("MATCH (n) WHERE n.id = ${user_input} RETURN n", False),
        ("MATCH (n) WHERE n.id = <USER_ID> RETURN n", False),
        ("ok", False),  # too short
    ])
    def test_validate_cypher(self, query, should_pass):
        valid, err = self.validate(query)
        assert valid == should_pass, f"Expected valid={should_pass} for: {query!r}, err={err}"

    def test_write_block_returns_message(self):
        valid, err = self.validate("CREATE (n:Node) RETURN n")
        assert not valid
        assert "write" in err.lower()

    def test_placeholder_block_returns_message(self):
        valid, err = self.validate("MATCH (n) WHERE n.id = ${id} RETURN n LIMIT 50")
        assert not valid
        assert "placeholder" in err.lower()


# ─── NL→Cypher translation tests ─────────────────────────────────────────────

class TestNLToCypher:

    @pytest.mark.parametrize("question,expected_cypher_fragment", [
        (
            "Which services have CRITICAL CVEs?",
            "CRITICAL",
        ),
        (
            "Show me all authentication functions",
            "Function",
        ),
        (
            "Which endpoints expose PII?",
            "exposes_pii",
        ),
        (
            "What are the dead code functions in the auth service?",
            "RUNTIME_CALLS",
        ),
        (
            "Show PII flows to unregulated services",
            "FLOWS_TO",
        ),
    ])
    @patch("layer5.nl_to_cypher.run_query")
    @patch("layer5.nl_to_cypher._get_client")
    def test_nl_questions_produce_valid_cypher(
        self, mock_get_client, mock_run_query, question, expected_cypher_fragment
    ):
        cypher = f"MATCH (n:{expected_cypher_fragment}) WHERE n.deprecated_at IS NULL RETURN n LIMIT 50"
        summary_text = "2 results found indicating moderate risk."

        client = MagicMock()
        client.messages.create.side_effect = [
            _make_claude_response(cypher),
            _make_claude_response(summary_text),
        ]
        mock_get_client.return_value = client
        mock_run_query.return_value = [{"n": {"id": "test"}}]

        from layer5.nl_to_cypher import translate_and_execute
        result = translate_and_execute(question)

        assert result.error is None, f"Unexpected error: {result.error}"
        assert result.cypher, "Cypher should not be empty"
        assert result.record_count > 0
        assert result.summary

    @patch("layer5.nl_to_cypher.run_query")
    @patch("layer5.nl_to_cypher._get_client")
    def test_cache_hit_detected(self, mock_get_client, mock_run_query):
        client = MagicMock()
        client.messages.create.side_effect = [
            _make_claude_response(
                "MATCH (f:Function) WHERE f.deprecated_at IS NULL RETURN f LIMIT 50",
                cache_read=1500,
            ),
            _make_claude_response("Summary text here."),
        ]
        mock_get_client.return_value = client
        mock_run_query.return_value = [{"f": {}}]

        from layer5.nl_to_cypher import translate_and_execute
        result = translate_and_execute("Show all functions")
        assert result.cached is True

    @patch("layer5.nl_to_cypher.run_query")
    @patch("layer5.nl_to_cypher._get_client")
    def test_write_operation_blocked(self, mock_get_client, mock_run_query):
        client = MagicMock()
        client.messages.create.return_value = _make_claude_response(
            "CREATE (n:Node) RETURN n"
        )
        mock_get_client.return_value = client

        from layer5.nl_to_cypher import translate_and_execute
        result = translate_and_execute("Inject something bad")
        assert result.error is not None
        assert "write" in result.error.lower()
        mock_run_query.assert_not_called()

    @patch("layer5.nl_to_cypher._get_client")
    def test_claude_api_error_returns_error_result(self, mock_get_client):
        import anthropic
        client = MagicMock()
        client.messages.create.side_effect = anthropic.APIError(
            "Rate limit", request=MagicMock(), body=None
        )
        mock_get_client.return_value = client

        from layer5.nl_to_cypher import translate_and_execute
        result = translate_and_execute("Any question")
        assert result.error is not None
        assert result.records == []

    @patch("layer5.nl_to_cypher.run_query")
    @patch("layer5.nl_to_cypher._get_client")
    def test_markdown_fences_stripped(self, mock_get_client, mock_run_query):
        client = MagicMock()
        client.messages.create.side_effect = [
            _make_claude_response(
                "```cypher\nMATCH (f:Function) RETURN f LIMIT 50\n```"
            ),
            _make_claude_response("Summary."),
        ]
        mock_get_client.return_value = client
        mock_run_query.return_value = [{}]

        from layer5.nl_to_cypher import translate_and_execute
        result = translate_and_execute("Show functions")
        assert "```" not in result.cypher


# ─── Weaviate search tests ─────────────────────────────────────────────────────

class TestWeaviateIndex:

    def _make_weaviate_object(self, neo4j_id: str, description: str, certainty: float):
        obj = MagicMock()
        obj.properties = {"neo4j_id": neo4j_id, "description": description}
        obj.metadata = MagicMock()
        obj.metadata.certainty = certainty
        return obj

    @patch("layer5.weaviate_index._weaviate_client")
    def test_search_functions_returns_results(self, mock_weaviate_client):
        mock_client = MagicMock()
        mock_weaviate_client.return_value = mock_client

        objects = [
            self._make_weaviate_object("fn:auth:validate_token", "validate_token in auth/jwt.py", 0.92),
            self._make_weaviate_object("fn:auth:refresh_token", "refresh_token in auth/jwt.py", 0.78),
        ]
        query_result = MagicMock()
        query_result.objects = objects
        mock_client.collections.get.return_value.query.near_text.return_value = query_result

        from layer5.weaviate_index import WeaviateIndex
        idx = WeaviateIndex()
        idx._client = mock_client

        results = idx.search_functions("authentication", limit=5)
        assert len(results) == 2
        assert results[0].certainty >= 0.5
        assert results[0].node_type == "Function"
        assert results[0].neo4j_id == "fn:auth:validate_token"

    @patch("layer5.weaviate_index._weaviate_client")
    def test_search_all_merges_and_sorts(self, mock_weaviate_client):
        mock_client = MagicMock()
        mock_weaviate_client.return_value = mock_client

        fn_obj = self._make_weaviate_object("fn:auth:login", "login function", 0.95)
        ep_obj = self._make_weaviate_object("ep:auth:/login", "POST /login endpoint", 0.88)
        vuln_obj = self._make_weaviate_object("vuln:CVE-2023-1", "CVE-2023-1 in auth", 0.70)

        def side_effect(class_name):
            collection = MagicMock()
            if class_name == "LsigFunction":
                collection.query.near_text.return_value = MagicMock(objects=[fn_obj])
            elif class_name == "LsigEndpoint":
                collection.query.near_text.return_value = MagicMock(objects=[ep_obj])
            else:
                collection.query.near_text.return_value = MagicMock(objects=[vuln_obj])
            return collection

        mock_client.collections.get.side_effect = side_effect

        from layer5.weaviate_index import WeaviateIndex
        idx = WeaviateIndex()
        idx._client = mock_client

        results = idx.search_all("authentication login", limit=3)
        assert len(results) >= 2
        # Sorted by certainty descending
        for i in range(len(results) - 1):
            assert results[i].certainty >= results[i + 1].certainty

    def test_stable_uuid_deterministic(self):
        from layer5.weaviate_index import _stable_uuid
        uuid1 = _stable_uuid("fn:auth:validate_token")
        uuid2 = _stable_uuid("fn:auth:validate_token")
        uuid3 = _stable_uuid("fn:auth:refresh_token")
        assert uuid1 == uuid2
        assert uuid1 != uuid3

    @patch("layer5.weaviate_index.run_query")
    @patch("layer5.weaviate_index._weaviate_client")
    def test_sync_functions_upserts_batch(self, mock_weaviate_client, mock_run_query):
        mock_client = MagicMock()
        mock_weaviate_client.return_value = mock_client

        mock_run_query.return_value = MOCK_FUNCTIONS
        batch_ctx = MagicMock()
        mock_client.collections.get.return_value.batch.dynamic.return_value.__enter__ = MagicMock(return_value=batch_ctx)
        mock_client.collections.get.return_value.batch.dynamic.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.schema.get.return_value = {"classes": [{"class": "LsigFunction"}, {"class": "LsigEndpoint"}, {"class": "LsigVulnerability"}]}

        from layer5.weaviate_index import WeaviateIndex
        idx = WeaviateIndex()
        idx._client = mock_client
        count = idx.sync_functions()
        assert count == len(MOCK_FUNCTIONS)

    def test_description_builders(self):
        from layer5.weaviate_index import (
            _function_description,
            _endpoint_description,
            _vulnerability_description,
        )
        fn_desc = _function_description(MOCK_FUNCTIONS[0])
        assert "validate_token" in fn_desc
        assert "auth" in fn_desc

        ep_desc = _endpoint_description(MOCK_ENDPOINTS[0])
        assert "/login" in ep_desc
        assert "PII" in ep_desc

        vuln_desc = _vulnerability_description(MOCK_VULNS[0])
        assert "CVE-2023-1234" in vuln_desc
        assert "CRITICAL" in vuln_desc
        assert "IN-KEV" in vuln_desc


# ─── VictoriaMetrics tests ─────────────────────────────────────────────────────

class TestVictoriaMetrics:

    def test_write_call_count_format(self):
        from layer5.victoria_metrics import VictoriaMetricsClient, _build_prometheus_line
        line = _build_prometheus_line(
            "lsig_function_calls_total",
            {"service": "auth", "function": "validate_token", "file": "auth/jwt.py"},
            450.0,
            1700000000000,
        )
        assert "lsig_function_calls_total" in line
        assert 'service="auth"' in line
        assert "450.0" in line
        assert "1700000000000" in line

    @patch("layer5.victoria_metrics._http_post_raw")
    def test_write_returns_true_on_200(self, mock_post):
        mock_post.return_value = 200
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient("http://localhost:8428")
        assert vm.write(["lsig_test_metric 1.0"]) is True

    @patch("layer5.victoria_metrics._http_post_raw")
    def test_write_returns_false_on_error(self, mock_post):
        mock_post.side_effect = ConnectionRefusedError("VM down")
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient("http://localhost:8428")
        assert vm.write(["lsig_test_metric 1.0"]) is False

    @patch("layer5.victoria_metrics._http_get_json")
    def test_query_returns_series(self, mock_get):
        mock_get.return_value = {
            "data": {
                "result": [
                    {"metric": {"__name__": "lsig_function_calls_total", "service": "auth"},
                     "value": [1700000000, "450"]}
                ]
            }
        }
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        results = vm.query("lsig_function_calls_total")
        assert len(results) == 1
        assert results[0]["metric"]["service"] == "auth"

    @patch("layer5.victoria_metrics._http_get_json")
    def test_query_range_returns_time_series(self, mock_get):
        now = datetime.now(timezone.utc)
        mock_get.return_value = {
            "data": {
                "result": [
                    {
                        "metric": {"__name__": "lsig_function_calls_total", "function": "validate_token"},
                        "values": [
                            [1700000000, "100"],
                            [1700003600, "150"],
                            [1700007200, "200"],
                        ],
                    }
                ]
            }
        }
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        series = vm.query_range(
            "lsig_function_calls_total",
            start=now - timedelta(hours=3),
            end=now,
        )
        assert len(series) == 1
        assert len(series[0].timestamps) == 3
        assert series[0].values[0] == 100.0

    @patch("layer5.victoria_metrics._http_get_json")
    def test_query_returns_empty_on_error(self, mock_get):
        mock_get.side_effect = ConnectionRefusedError("VM down")
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        assert vm.query("any_metric") == []

    @patch("layer5.victoria_metrics._http_post_raw")
    def test_write_empty_lines_returns_true(self, mock_post):
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        assert vm.write([]) is True
        mock_post.assert_not_called()

    @patch("layer5.victoria_metrics._http_get_json")
    def test_query_certificate_p95(self, mock_get):
        mock_get.return_value = {
            "data": {"result": [{"value": [1700000000, "0.245"]}]}
        }
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        p95 = vm.query_certificate_p95()
        assert p95 == pytest.approx(0.245)

    @patch("layer5.victoria_metrics._http_get_json")
    def test_health_returns_true_when_reachable(self, mock_get):
        mock_get.return_value = {"status": "ok"}
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        assert vm.health() is True

    @patch("layer5.victoria_metrics._http_get_json")
    def test_health_returns_false_when_down(self, mock_get):
        mock_get.side_effect = ConnectionRefusedError()
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        assert vm.health() is False


# ─── Graph API endpoint tests ─────────────────────────────────────────────────

class TestGraphAPI:

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        with patch("layer5.graph_api.warm_schema_cache"), \
             patch("layer5.graph_api.WeaviateIndex"):
            from layer5.graph_api import app
            return TestClient(app, raise_server_exceptions=True)

    @patch("layer5.graph_api.translate_and_execute")
    def test_nl_query_endpoint(self, mock_translate, client):
        from layer5.nl_to_cypher import NLQueryResult
        mock_translate.return_value = NLQueryResult(
            question="Show critical CVEs",
            cypher="MATCH (v:Vulnerability {severity:'CRITICAL'}) RETURN v LIMIT 50",
            records=[{"v": {"cve_id": "CVE-2023-1234"}}],
            summary="1 critical CVE found affecting payments service.",
            cached=True,
            latency_ms=320,
            record_count=1,
        )
        resp = client.post("/query/nl", json={"question": "Show critical CVEs"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["record_count"] == 1
        assert data["cached"] is True
        assert "CVE" in data["cypher"]

    @patch("layer5.graph_api.translate_and_execute")
    def test_nl_query_propagates_error(self, mock_translate, client):
        from layer5.nl_to_cypher import NLQueryResult
        mock_translate.return_value = NLQueryResult(
            question="bad question",
            cypher="", records=[], summary="",
            cached=False, latency_ms=100, record_count=0,
            error="Generated Cypher failed validation: Query contains write operations",
        )
        resp = client.post("/query/nl", json={"question": "bad question"})
        assert resp.status_code == 400

    @patch("layer5.graph_api.get_vm")
    @patch("layer5.graph_api.run_query")
    def test_service_summary_returns_all_sections(self, mock_run_query, mock_vm, client):
        mock_vm.return_value = MagicMock(query_certificate_p95=MagicMock(return_value=0.3))
        mock_run_query.side_effect = [
            [{"function_count": 142, "endpoint_count": 28}],  # graph stats
            [{"live_functions": 100, "dead_functions": 42, "total_calls_24h": 5000}],  # runtime
            [{"reachability": "CRITICAL", "count": 2}],  # security
            [{"pii_field_count": 5, "pii_types": ["EMAIL"]}],  # pii
            [{"scope": ["PCI"], "confidence": "HIGH"}],  # regulatory
            [{"team": "@myorg/auth", "functions": 80}],  # ownership
        ]
        resp = client.get("/query/service_summary?service=auth")
        assert resp.status_code == 200
        data = resp.json()
        assert "graph" in data
        assert "security" in data
        assert "ownership" in data

    @patch("layer5.graph_api.get_index")
    def test_search_functions_endpoint(self, mock_get_index, client):
        from layer5.weaviate_index import SearchResult
        mock_index = MagicMock()
        mock_index.search_functions.return_value = [
            SearchResult(
                neo4j_id="fn:auth:validate_token",
                description="validate_token in auth/jwt.py",
                certainty=0.92,
                node_type="Function",
            )
        ]
        mock_get_index.return_value = mock_index

        resp = client.get("/search/functions?q=authentication&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 1
        assert data["results"][0]["certainty"] == pytest.approx(0.92)

    @patch("layer5.graph_api.get_index")
    def test_search_all_endpoint(self, mock_get_index, client):
        from layer5.weaviate_index import SearchResult
        mock_index = MagicMock()
        mock_index.search_all.return_value = [
            SearchResult("fn:auth:login", "login fn", 0.95, "Function"),
            SearchResult("ep:auth:/login", "POST /login", 0.88, "APIEndpoint"),
        ]
        mock_get_index.return_value = mock_index

        resp = client.get("/search/all?q=login&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 2

    @patch("layer5.graph_api.get_vm")
    def test_metrics_system_endpoint(self, mock_get_vm, client):
        mock_vm = MagicMock()
        mock_vm.health.return_value = True
        mock_vm.query_certificate_p95.return_value = 0.245
        mock_vm.query_false_positive_reduction_rate.return_value = 0.73
        mock_get_vm.return_value = mock_vm

        resp = client.get("/metrics/system")
        assert resp.status_code == 200
        data = resp.json()
        assert data["victoriametrics_healthy"] is True
        assert data["certificate_p95_seconds"] == pytest.approx(0.245)
        assert data["cve_fp_reduction_rate"] == pytest.approx(0.73)


# ─── Acceptance criteria test ─────────────────────────────────────────────────

class TestLayer5AcceptanceCriteria:
    """
    AC-L5-1: 5+ NL queries produce valid Cypher with results (tested in TestNLToCypher)
    AC-L5-2: Prompt caching detected on second call with same schema
    AC-L5-3: Semantic search returns results with certainty >= 0.5
    AC-L5-4: VictoriaMetrics write+query round-trip succeeds
    AC-L5-5: All write operations blocked by validate_cypher
    """

    @patch("layer5.nl_to_cypher.run_query")
    @patch("layer5.nl_to_cypher._get_client")
    def test_ac_prompt_caching_second_call(self, mock_get_client, mock_run_query):
        """AC-L5-2: Second call shows cache_read_input_tokens > 0."""
        client = MagicMock()
        client.messages.create.side_effect = [
            # First call: cache miss
            _make_claude_response(
                "MATCH (f:Function) RETURN f LIMIT 50", cache_read=0
            ),
            _make_claude_response("Summary 1."),
            # Second call: cache hit
            _make_claude_response(
                "MATCH (f:Function) RETURN f LIMIT 50", cache_read=1500
            ),
            _make_claude_response("Summary 2."),
        ]
        mock_get_client.return_value = client
        mock_run_query.return_value = [{"f": {}}]

        from layer5.nl_to_cypher import translate_and_execute
        r1 = translate_and_execute("Show all functions")
        r2 = translate_and_execute("Show all functions again")

        assert r1.cached is False
        assert r2.cached is True

    @patch("layer5.weaviate_index._weaviate_client")
    def test_ac_semantic_search_certainty(self, mock_weaviate_client):
        """AC-L5-3: Auth semantic search returns results with certainty >= 0.5."""
        mock_client = MagicMock()
        mock_weaviate_client.return_value = mock_client

        objects = [
            MagicMock(
                properties={"neo4j_id": "fn:auth:validate_token", "description": "validate_token"},
                metadata=MagicMock(certainty=0.92),
            ),
        ]
        mock_client.collections.get.return_value.query.near_text.return_value = MagicMock(objects=objects)

        from layer5.weaviate_index import WeaviateIndex
        idx = WeaviateIndex()
        idx._client = mock_client

        results = idx.search_functions("auth")
        assert len(results) > 0
        assert all(r.certainty >= 0.5 for r in results)

    @patch("layer5.victoria_metrics._http_get_json")
    @patch("layer5.victoria_metrics._http_post_raw")
    def test_ac_vm_write_query_round_trip(self, mock_post, mock_get):
        """AC-L5-4: Write a metric, query it back, values match."""
        mock_post.return_value = 200
        mock_get.return_value = {
            "data": {
                "result": [
                    {"metric": {"service": "auth", "function": "validate_token"},
                     "value": [1700000000, "450"]}
                ]
            }
        }
        from layer5.victoria_metrics import VictoriaMetricsClient
        vm = VictoriaMetricsClient()
        assert vm.write_call_count("auth", "validate_token", 450) is True
        results = vm.query('lsig_function_calls_total{service="auth"}')
        assert len(results) == 1
        assert float(results[0]["value"][1]) == 450.0

    def test_ac_all_write_ops_blocked(self):
        """AC-L5-5: validate_cypher must block every known write operation."""
        from layer5.nl_to_cypher import validate_cypher
        write_ops = [
            "CREATE (n:Node) RETURN n",
            "MERGE (n:Node {id: 'x'}) RETURN n",
            "MATCH (n) SET n.prop = 'evil'",
            "MATCH (n) DELETE n",
            "MATCH (n) DETACH DELETE n",
            "MATCH (n) REMOVE n.prop",
            "DROP INDEX ON :Function(id)",
            "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {})",
            "LOAD CSV FROM 'http://evil.com' AS row RETURN row",
        ]
        for query in write_ops:
            valid, err = validate_cypher(query)
            assert not valid, f"Should have blocked: {query!r}"
