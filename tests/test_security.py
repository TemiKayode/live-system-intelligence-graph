"""
Layer 3 integration tests — Security Posture Engine.

Tests cover:
  1. CycloneDX SBOM parsing
  2. Version range matching
  3. CVE ingestion from OSV (mocked + live)
  4. Reachability engine — all three steps, each path
  5. Reachability false positive reduction acceptance criterion
  6. Nuclei path matching
  7. Security API endpoints

Run:
    pytest tests/test_security.py -v
    pytest tests/test_security.py -v -m "not neo4j and not slow"
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from layer3.cve_ingester import (
    parse_cyclonedx, Component, version_in_range, _build_vuln_record,
    _severity_from_osv, fetch_epss, is_in_kev,
)
from layer3.reachability import (
    Reachability, ReachabilityResult, compute_reachability,
    check_static_reachability, check_runtime_reachability,
    check_attack_surface_reachability,
)
from layer3.nuclei_runner import _path_to_pattern, _extract_paths


# ─── SBOM parsing tests ───────────────────────────────────────────────────────

SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "name": "django",
            "version": "3.2.8",
            "purl": "pkg:pypi/django@3.2.8",
            "cpe": "cpe:2.3:a:djangoproject:django:3.2.8:*:*:*:*:*:*:*",
            "licenses": [{"id": "BSD-3-Clause"}],
        },
        {
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
            "cpe": "",
            "licenses": [],
        },
        {
            "name": "lodash",
            "version": "4.17.15",
            "purl": "pkg:npm/lodash@4.17.15",
            "licenses": [{"id": "MIT"}],
        },
        {
            # Missing version — should be skipped
            "name": "no-version-pkg",
            "purl": "pkg:pypi/no-version-pkg",
        },
    ],
}


class TestSBOMParsing:
    @pytest.fixture
    def sbom_path(self, tmp_path):
        p = tmp_path / "sbom.json"
        p.write_text(json.dumps(SAMPLE_SBOM))
        return p

    def test_parses_components(self, sbom_path):
        from layer3.sbom_ingester import parse_cyclonedx
        components = parse_cyclonedx(sbom_path)
        assert len(components) == 3  # no-version-pkg excluded

    def test_ecosystem_derived_from_purl(self, sbom_path):
        from layer3.sbom_ingester import parse_cyclonedx
        comps = {c.name: c for c in parse_cyclonedx(sbom_path)}
        assert comps["django"].ecosystem == "pypi"
        assert comps["lodash"].ecosystem == "npm"

    def test_cpe_extracted(self, sbom_path):
        from layer3.sbom_ingester import parse_cyclonedx
        comps = {c.name: c for c in parse_cyclonedx(sbom_path)}
        assert "djangoproject" in comps["django"].cpe

    def test_licenses_extracted(self, sbom_path):
        from layer3.sbom_ingester import parse_cyclonedx
        comps = {c.name: c for c in parse_cyclonedx(sbom_path)}
        assert "BSD-3-Clause" in comps["django"].licenses

    def test_missing_version_excluded(self, sbom_path):
        from layer3.sbom_ingester import parse_cyclonedx
        names = [c.name for c in parse_cyclonedx(sbom_path)]
        assert "no-version-pkg" not in names


# ─── Version range matching tests ────────────────────────────────────────────

class TestVersionRangeMatching:
    def test_version_in_fixed_range(self):
        ranges = [{"introduced": "1.0.0", "fixed": "2.0.0"}]
        assert version_in_range("1.5.0", ranges) is True

    def test_version_below_introduced_not_in_range(self):
        ranges = [{"introduced": "2.0.0", "fixed": "3.0.0"}]
        assert version_in_range("1.9.9", ranges) is False

    def test_version_at_fixed_not_in_range(self):
        # [introduced, fixed) — fixed is exclusive
        ranges = [{"introduced": "1.0.0", "fixed": "2.0.0"}]
        assert version_in_range("2.0.0", ranges) is False

    def test_version_in_last_affected_range(self):
        ranges = [{"introduced": "3.0.0", "last_affected": "3.2.8"}]
        assert version_in_range("3.2.8", ranges) is True
        assert version_in_range("3.2.9", ranges) is False

    def test_open_ended_range(self):
        ranges = [{"introduced": "0"}]
        assert version_in_range("99.99.99", ranges) is True

    def test_exact_version_match(self):
        assert version_in_range("1.2.3", []) is False
        # Exact versions checked separately in cve_ingester, not via ranges

    def test_multiple_ranges_any_match(self):
        ranges = [
            {"introduced": "1.0.0", "fixed": "1.5.0"},
            {"introduced": "2.0.0", "fixed": "2.5.0"},
        ]
        assert version_in_range("1.3.0", ranges) is True
        assert version_in_range("2.3.0", ranges) is True
        assert version_in_range("1.9.0", ranges) is False


# ─── CVE ingestion tests ──────────────────────────────────────────────────────

class TestCVEIngestion:
    SAMPLE_OSV_RECORD = {
        "id": "GHSA-test-1234-abcd",
        "aliases": ["CVE-2024-12345"],
        "published": "2024-01-15T00:00:00Z",
        "affected": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "versions": ["3.2.8"],
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "3.0.0"}, {"fixed": "3.2.9"},
                ]}],
                "ecosystem_specific": {"functions": ["django.db.models.sql.compiler.SQLCompiler.as_sql"]},
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL"},
    }

    def test_build_vuln_record(self):
        with patch("layer3.cve_ingester.fetch_epss", return_value=0.85):
            with patch("layer3.cve_ingester.is_in_kev", return_value=True):
                rec = _build_vuln_record("GHSA-test-1234-abcd", self.SAMPLE_OSV_RECORD)

        assert rec.cve_id == "CVE-2024-12345"
        assert rec.affected_package == "django"
        assert rec.affected_ecosystem == "pypi"
        assert "3.2.8" in rec.affected_versions
        assert rec.in_kev is True
        assert rec.epss_score == 0.85
        assert len(rec.vulnerable_functions) > 0

    def test_severity_critical_from_cvss(self):
        sev = _severity_from_osv(self.SAMPLE_OSV_RECORD)
        assert sev == "CRITICAL"

    def test_severity_fallback_to_database_specific(self):
        rec = {
            "database_specific": {"severity": "HIGH"},
            "severity": [],
            "aliases": [],
        }
        with patch("layer3.cve_ingester.fetch_epss", return_value=0.0):
            sev = _severity_from_osv(rec)
        assert sev == "HIGH"

    def test_epss_cached_after_first_call(self):
        with patch("layer3.cve_ingester._http_get", return_value={"data": [{"epss": "0.5"}]}) as mock:
            fetch_epss("CVE-2024-99999")
            fetch_epss("CVE-2024-99999")  # second call should use cache
        # HTTP should only be called once
        assert mock.call_count == 1

    def test_kev_membership(self):
        kev_data = {"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}
        with patch("layer3.cve_ingester._http_get", return_value=kev_data):
            # Clear cache
            import layer3.cve_ingester as m
            m._kev_loaded_at = None
            assert is_in_kev("CVE-2024-12345") is True
            assert is_in_kev("CVE-2024-99999") is False


# ─── Reachability engine tests ────────────────────────────────────────────────

class TestReachabilityEngine:
    """Unit tests using mocked Neo4j queries."""

    def _mock_static(self, paths: list[dict]):
        return patch("layer3.reachability.check_static_reachability", return_value=paths)

    def _mock_runtime(self, evidence: list[dict]):
        return patch("layer3.reachability.check_runtime_reachability", return_value=evidence)

    def _mock_surface(self, external: dict | None):
        return patch("layer3.reachability.check_attack_surface_reachability",
                     return_value=external)

    def _mock_neo4j(self):
        return patch("layer3.reachability.run_query", return_value=[])

    def test_not_reachable_when_no_static_path(self):
        with self._mock_static([]), self._mock_neo4j():
            result = compute_reachability("CVE-X", "dep:1", "svc", ["vuln_func"])
        assert result.reachability == Reachability.NOT_REACHABLE
        assert result.static_path_found is False

    def test_low_when_static_path_but_no_runtime(self):
        static_paths = [{
            "endpoint_id": "svc:GET:/api/users",
            "handler_id": "svc:handlers.py:handle:10",
            "path_node_ids": ["svc:handlers.py:handle:10", "svc:db.py:query:50"],
        }]
        with self._mock_static(static_paths), self._mock_runtime([]), self._mock_neo4j():
            result = compute_reachability("CVE-X", "dep:1", "svc", ["query"])
        assert result.reachability == Reachability.LOW
        assert result.static_path_found is True
        assert result.runtime_evidence is False

    def test_high_when_static_and_runtime_but_not_external(self):
        static_paths = [{
            "endpoint_id": "svc:GET:/api/users",
            "handler_id": "svc:handlers.py:handle:10",
            "path_node_ids": ["svc:handlers.py:handle:10"],
        }]
        runtime_evidence = [{"func_id": "svc:handlers.py:handle:10", "count_24h": 500}]
        with self._mock_static(static_paths), \
             self._mock_runtime(runtime_evidence), \
             self._mock_surface(None), \
             self._mock_neo4j():
            result = compute_reachability("CVE-X", "dep:1", "svc", ["handle"])
        assert result.reachability == Reachability.HIGH
        assert result.runtime_evidence is True
        assert result.externally_reachable is False
        assert result.runtime_call_count_24h == 500

    def test_critical_when_externally_reachable(self):
        static_paths = [{
            "endpoint_id": "svc:GET:/api/users",
            "handler_id": "svc:handlers.py:handle:10",
            "path_node_ids": ["svc:handlers.py:handle:10"],
        }]
        runtime_evidence = [{"func_id": "svc:handlers.py:handle:10", "count_24h": 1000}]
        external = {"url": "https://api.example.com/api/users", "external_id": "ext:1"}
        with self._mock_static(static_paths), \
             self._mock_runtime(runtime_evidence), \
             self._mock_surface(external), \
             self._mock_neo4j():
            result = compute_reachability("CVE-X", "dep:1", "svc", ["handle"])
        assert result.reachability == Reachability.CRITICAL
        assert result.externally_reachable is True
        assert result.external_url == "https://api.example.com/api/users"

    def test_multiple_endpoints_one_external_sufficient_for_critical(self):
        """If even one entry endpoint is external → CRITICAL."""
        static_paths = [
            {"endpoint_id": "svc:GET:/internal/health",
             "handler_id": "h1", "path_node_ids": ["h1"]},
            {"endpoint_id": "svc:POST:/api/login",
             "handler_id": "h2", "path_node_ids": ["h2"]},
        ]
        runtime_evidence = [{"func_id": "h1", "count_24h": 10}]
        # Only the second endpoint is external
        def surface_side_effect(ep_id):
            if ep_id == "svc:POST:/api/login":
                return {"url": "https://api.example.com/api/login", "external_id": "ext:2"}
            return None

        with self._mock_static(static_paths), \
             self._mock_runtime(runtime_evidence), \
             patch("layer3.reachability.check_attack_surface_reachability",
                   side_effect=surface_side_effect), \
             self._mock_neo4j():
            result = compute_reachability("CVE-X", "dep:1", "svc", ["vuln"])
        assert result.reachability == Reachability.CRITICAL


# ─── Acceptance criterion: 70% false positive reduction ──────────────────────

@pytest.mark.neo4j
@pytest.mark.slow
class TestFalsePositiveReduction:
    """
    End-to-end acceptance criterion test.

    Seeds a Python service with:
      - 200 dependencies, 15 known CVEs
      - Runtime evidence for only a subset of the call paths
      - Only 2 externally reachable endpoints

    Verifies the CRITICAL CVE count is ≤30% of the raw CVE count (≥70% reduction).
    """

    @pytest.fixture(scope="class")
    def seeded_security_graph(self):
        from layer1.neo4j_client import run_query, upsert_node
        service = "fp-reduction-test"
        upsert_node("Service", id_props={"id": service}, extra_props={"name": service})

        # Seed 200 dependencies, 15 of which have CVEs
        for i in range(200):
            dep_id = f"{service}:pypi:pkg-{i}:1.0.{i}"
            upsert_node("Dependency", id_props={"id": dep_id}, extra_props={
                "name": f"pkg-{i}", "version": f"1.0.{i}",
                "ecosystem": "pypi", "service": service,
            })

        # Seed 15 vulnerabilities linked to the first 15 dependencies
        vuln_ids = []
        for i in range(15):
            vuln_id = f"CVE-TEST-{1000+i}"
            dep_id = f"{service}:pypi:pkg-{i}:1.0.{i}"
            func_name = f"vulnerable_func_{i}"
            upsert_node("Vulnerability", id_props={"id": vuln_id}, extra_props={
                "cve_id": vuln_id, "osv_id": f"GHSA-test-{i}",
                "affected_package": f"pkg-{i}",
                "affected_versions": [f"1.0.{i}"],
                "vulnerable_functions": [func_name],
                "severity": "HIGH",
                "epss_score": 0.5,
                "in_kev": False,
                "published_at": "2024-01-01T00:00:00Z",
                "aliases": [],
            })
            run_query(
                "MATCH (d:Dependency {id: $did}) MATCH (v:Vulnerability {id: $vid}) "
                "MERGE (d)-[r:HAS_VULN]->(v) SET r.severity='HIGH', r.reachability='UNKNOWN', "
                "r.epss_score=0.5, r.in_kev=false",
                {"did": dep_id, "vid": vuln_id},
            )
            vuln_ids.append((vuln_id, dep_id, func_name))

        # Seed functions — only 4 of 15 vulnerable functions have runtime evidence
        # and only 2 entry endpoints
        for i, (vuln_id, dep_id, func_name) in enumerate(vuln_ids):
            fn_id = f"{service}:handlers.py:{func_name}:{i+1}"
            upsert_node("Function", id_props={"id": fn_id}, extra_props={
                "name": func_name, "file": "handlers.py",
                "line": i + 1, "language": "python", "service": service,
            })

        # Create 2 API endpoints covering only the first 4 vulnerable functions
        for i in range(2):
            ep_id = f"{service}:GET:/api/route-{i}"
            upsert_node("APIEndpoint", id_props={"id": ep_id}, extra_props={
                "path": f"/api/route-{i}", "method": "GET",
                "service": service, "authenticated": True,
            })
            handler_fn_id = f"{service}:handlers.py:vulnerable_func_{i}:{i+1}"
            run_query(
                "MATCH (ep:APIEndpoint {id: $eid}) MATCH (f:Function {id: $fid}) "
                "MERGE (ep)-[:HANDLED_BY]->(f)",
                {"eid": ep_id, "fid": handler_fn_id},
            )
            # Add runtime evidence for these 2 endpoints only
            run_query(
                "MATCH (f:Function {id: $fid}) MERGE (f)-[r:RUNTIME_CALLS]->(f) "
                "SET r.call_count_24h=500, r.last_seen=datetime()",
                {"fid": handler_fn_id},
            )

        # Add ExternalEndpoint for only 1 route (making CRITICAL count = 1 at most)
        ext_id = "ext-fp-test-0"
        ep_id_0 = f"{service}:GET:/api/route-0"
        upsert_node("ExternalEndpoint", id_props={"id": ext_id}, extra_props={
            "url": "https://fp-test.example.com/api/route-0",
            "service": service, "discovered_at": "2026-05-09T00:00:00Z",
        })
        run_query(
            "MATCH (ext:ExternalEndpoint {id: $eid}) MATCH (ep:APIEndpoint {id: $epid}) "
            "MERGE (ext)-[:MAPS_TO]->(ep)",
            {"eid": ext_id, "epid": ep_id_0},
        )

        yield service

        # Cleanup
        run_query("MATCH (n) WHERE n.service = $svc DETACH DELETE n", {"svc": service})

    def test_false_positive_reduction_70_percent(self, seeded_security_graph):
        from layer3.reachability import run_for_service

        service = seeded_security_graph
        results = run_for_service(service)

        total_vulns = len(results)
        critical_count = sum(1 for r in results if r.reachability == Reachability.CRITICAL)
        high_count = sum(1 for r in results if r.reachability == Reachability.HIGH)
        not_reachable = sum(1 for r in results
                            if r.reachability in (Reachability.NOT_REACHABLE, Reachability.LOW))

        assert total_vulns == 15, f"Expected 15 vulns, got {total_vulns}"

        # Raw CVE count = 15. CRITICAL+HIGH should be ≤ 4 (≤30% = 4.5)
        actionable = critical_count + high_count
        raw_count = total_vulns
        reduction_pct = (raw_count - actionable) / raw_count

        assert reduction_pct >= 0.70, (
            f"False positive reduction {reduction_pct:.1%} < 70% "
            f"(CRITICAL={critical_count}, HIGH={high_count}, total={total_vulns})"
        )
        assert critical_count <= 1, (
            f"Expected at most 1 CRITICAL (1 external endpoint), got {critical_count}"
        )


# ─── Nuclei path matching tests ───────────────────────────────────────────────

class TestNucleiPathMatching:
    def test_numeric_segment_replaced_with_wildcard(self):
        pattern = _path_to_pattern("/api/v1/users/123")
        assert "{id}" in pattern
        assert "123" not in pattern

    def test_uuid_segment_replaced(self):
        pattern = _path_to_pattern("/api/v1/items/550e8400-e29b-41d4-a716-446655440000")
        assert "{uuid}" in pattern

    def test_non_numeric_path_unchanged(self):
        pattern = _path_to_pattern("/api/v1/health")
        assert pattern == "/api/v1/health"

    def test_extract_paths_from_nuclei_results(self):
        findings = [
            {"matched-at": "https://api.example.com/api/v1/users"},
            {"matched-at": "https://api.example.com/api/v1/health"},
            {"matched-at": "https://api.example.com/api/v1/users"},  # duplicate
            {"matched-at": ""},  # empty
            {},                   # missing
        ]
        paths = _extract_paths(findings)
        assert "/api/v1/users" in paths
        assert "/api/v1/health" in paths
        assert len([p for p in paths if p == "/api/v1/users"]) == 1  # deduped


# ─── Security API endpoint tests ──────────────────────────────────────────────

class TestSecurityAPIEndpoints:
    @pytest.fixture(scope="class")
    def api_client(self):
        from fastapi.testclient import TestClient
        from layer1.code_api import app
        return TestClient(app)

    def test_vulns_endpoint_returns_200(self, api_client):
        resp = api_client.get("/security/vulns?service=nonexistent-svc")
        assert resp.status_code == 200
        body = resp.json()
        assert "vulnerabilities" in body
        assert body["count"] == 0

    def test_vulns_reachability_filter(self, api_client):
        resp = api_client.get("/security/vulns?service=any&reachability=CRITICAL")
        assert resp.status_code == 200

    def test_blast_radius_returns_200(self, api_client):
        resp = api_client.get("/security/blast_radius?cve=CVE-0000-0000")
        assert resp.status_code == 200
        body = resp.json()
        assert "blast_radius" in body
        assert body["affected_service_count"] == 0

    def test_blast_radius_missing_cve_422(self, api_client):
        resp = api_client.get("/security/blast_radius")
        assert resp.status_code == 422

    def test_viz_blast_radius_returns_graph(self, api_client):
        resp = api_client.get("/viz/blast_radius?cve=CVE-0000-0000")
        assert resp.status_code == 200
        body = resp.json()
        assert "nodes" in body
        assert "links" in body
