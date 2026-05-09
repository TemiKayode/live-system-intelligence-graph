"""
Layer 6 integration tests — Change Impact Certificate Engine.

Acceptance criteria:
  AC-L6-1: Certificate generated in < 60s (validated via mocked backends)
  AC-L6-2: Certificate contains all four sections (functions, blast radius, security delta, narrative)
  AC-L6-3: HMAC-SHA256 signature is valid and tamper-evident
  AC-L6-4: Risk level correctly computed from security delta
  AC-L6-5: GitHub Check Run created and updated (mocked GitHub API)
  AC-L6-6: Certificate stored in Neo4j as Certificate node
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest


# ─── Fixtures ─────────────────────────────────────────────────────────────────

MOCK_FN_ROWS = [
    {
        "id": "fn:auth:validate_token",
        "name": "validate_token",
        "file": "auth/jwt.py",
        "owner_team": "@myorg/auth",
        "owner_email": "auth-team@example.com",
        "callers_count": 12,
        "runtime_callers_count": 8,
        "is_endpoint_handler": False,
    },
    {
        "id": "fn:auth:issue_token",
        "name": "issue_token",
        "file": "auth/jwt.py",
        "owner_team": "@myorg/auth",
        "owner_email": "auth-team@example.com",
        "callers_count": 3,
        "runtime_callers_count": 3,
        "is_endpoint_handler": True,
    },
]

MOCK_BLAST_ROWS = [
    {
        "caller_ids": ["fn:api:handle_request", "fn:payments:charge"],
        "endpoint_ids": ["ep:auth:/login"],
        "services": ["api", "payments"],
    }
]

MOCK_VULN_ROWS = [
    {
        "cve_id": "CVE-2023-9999",
        "severity": "CRITICAL",
        "reachability": "CRITICAL",
        "epss_score": 0.91,
        "in_kev": True,
    }
]

MOCK_PII_ROWS = [
    {
        "source_field": "email",
        "pii_type": "EMAIL",
        "dest_service": "analytics",
        "unregulated": True,
    }
]


# ─── Certificate engine tests ─────────────────────────────────────────────────

class TestCertificateEngine:

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_generate_certificate_structure(
        self, mock_run_query, mock_narrative, mock_vm
    ):
        mock_run_query.side_effect = [
            MOCK_FN_ROWS,   # resolve_changed_functions
            MOCK_BLAST_ROWS, # blast radius
            MOCK_VULN_ROWS, # CVE delta
            MOCK_PII_ROWS,  # PII flows
        ]
        mock_narrative.return_value = "This PR modifies auth JWT handling with high risk."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-42",
            changed_files=["auth/jwt.py"],
            service="auth",
        )

        # AC-L6-2: All four sections present
        assert len(cert.changed_functions) == 2
        assert cert.blast_radius is not None
        assert cert.security_delta is not None
        assert cert.narrative

        assert cert.changed_functions[0].function_name == "validate_token"
        assert cert.blast_radius.affected_services == ["api", "payments"]
        assert len(cert.security_delta.new_critical_vulns) == 1

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_certificate_generation_under_60s(
        self, mock_run_query, mock_narrative, mock_vm
    ):
        """AC-L6-1: Certificate must be generated in < 60 seconds."""
        mock_run_query.side_effect = [MOCK_FN_ROWS, MOCK_BLAST_ROWS, [], []]
        mock_narrative.return_value = "Summary."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate
        start = time.monotonic()
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-1",
            changed_files=["auth/jwt.py"],
            service="auth",
        )
        elapsed = time.monotonic() - start

        assert elapsed < 60, f"Certificate took {elapsed:.1f}s, must be < 60s"
        assert cert.generation_duration_ms < 60_000

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_signature_valid(self, mock_run_query, mock_narrative, mock_vm):
        """AC-L6-3: Certificate signature must be valid."""
        mock_run_query.side_effect = [MOCK_FN_ROWS, MOCK_BLAST_ROWS, [], []]
        mock_narrative.return_value = "Summary."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate, verify_certificate
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-2",
            changed_files=["auth/jwt.py"],
            service="auth",
        )
        cert_dict = asdict(cert)
        assert verify_certificate(cert_dict) is True

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_signature_tamper_evident(self, mock_run_query, mock_narrative, mock_vm):
        """AC-L6-3: Tampered certificate must fail verification."""
        mock_run_query.side_effect = [MOCK_FN_ROWS, MOCK_BLAST_ROWS, [], []]
        mock_narrative.return_value = "Summary."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate, verify_certificate
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-3",
            changed_files=["auth/jwt.py"],
            service="auth",
        )
        cert_dict = asdict(cert)
        cert_dict["risk_level"] = "NONE"  # tamper
        assert verify_certificate(cert_dict) is False

    @pytest.mark.parametrize("vuln_rows,pii_rows,blast_services,expected_risk", [
        # CRITICAL: KEV CVE reachable
        (
            [{"cve_id": "CVE-X", "severity": "CRITICAL", "reachability": "CRITICAL",
              "epss_score": 0.9, "in_kev": True}],
            [], [], "CRITICAL"
        ),
        # HIGH: CRITICAL CVE but not KEV
        (
            [{"cve_id": "CVE-Y", "severity": "CRITICAL", "reachability": "CRITICAL",
              "epss_score": 0.5, "in_kev": False}],
            [], [], "HIGH"
        ),
        # MEDIUM: no CRITICAL CVE but PII flows
        ([], [{"source_field": "email", "pii_type": "EMAIL",
               "dest_service": "analytics", "unregulated": True}],
         [], "MEDIUM"),
        # LOW: blast radius crosses services, no vulns
        ([], [], ["payments", "api"], "LOW"),
        # NONE: no issues
        ([], [], [], "NONE"),
    ])
    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_risk_level_computation(
        self, mock_run_query, mock_narrative, mock_vm,
        vuln_rows, pii_rows, blast_services, expected_risk
    ):
        """AC-L6-4: Risk level correctly computed from delta."""
        blast = [{"caller_ids": [], "endpoint_ids": [], "services": blast_services}] if blast_services else []
        mock_run_query.side_effect = [
            MOCK_FN_ROWS,
            blast or [{"caller_ids": [], "endpoint_ids": [], "services": []}],
            vuln_rows,
            pii_rows,
        ]
        mock_narrative.return_value = "Summary."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate
        cert = generate_certificate(
            pr_id=f"github:myorg/auth:PR-risk-{expected_risk}",
            changed_files=["auth/jwt.py"],
            service="auth",
        )
        assert cert.risk_level == expected_risk, (
            f"Expected {expected_risk}, got {cert.risk_level}"
        )

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_empty_changed_files_handled(self, mock_run_query, mock_narrative, mock_vm):
        """Empty file list produces a valid certificate with no functions."""
        mock_run_query.side_effect = [
            [],  # no functions
            [],  # no blast
            [],  # no CVEs
            [],  # no PII
        ]
        mock_narrative.return_value = "No functions changed."
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-empty",
            changed_files=[],
            service="auth",
        )
        assert cert.changed_functions == []
        assert cert.risk_level == "NONE"
        assert cert.signature != ""


# ─── Signing tests ────────────────────────────────────────────────────────────

class TestSigning:

    def test_sign_and_verify_round_trip(self):
        from layer6.certificate_engine import _sign_certificate, verify_certificate
        payload = {
            "certificate_id": "test-123",
            "pr_id": "PR-42",
            "risk_level": "HIGH",
            "service": "auth",
        }
        sig = _sign_certificate(payload)
        payload["signature"] = sig
        assert verify_certificate(payload) is True

    def test_verify_fails_with_wrong_field(self):
        from layer6.certificate_engine import _sign_certificate, verify_certificate
        payload = {"certificate_id": "test-456", "risk_level": "LOW"}
        sig = _sign_certificate(payload)
        payload["signature"] = sig
        payload["risk_level"] = "CRITICAL"  # tamper
        assert verify_certificate(payload) is False

    def test_verify_missing_signature_fails(self):
        from layer6.certificate_engine import verify_certificate
        assert verify_certificate({"certificate_id": "x", "risk_level": "NONE"}) is False


# ─── GitHub webhook tests ─────────────────────────────────────────────────────

class TestGitHubWebhook:

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from layer6.github_webhook import app
        return TestClient(app)

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_non_pr_event_ignored(self, client):
        resp = client.post(
            "/webhook/github",
            json={"action": "created"},
            headers={"X-GitHub-Event": "push"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_pr_closed_ignored(self, client):
        resp = client.post(
            "/webhook/github",
            json={"action": "closed", "pull_request": {}, "repository": {}},
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    @patch("layer6.github_webhook._get_pr_changed_files")
    @patch("layer6.github_webhook._create_check_run")
    @patch("layer6.github_webhook._run_certificate_job")
    def test_pr_opened_triggers_job(
        self, mock_job, mock_check, mock_files, client
    ):
        mock_check.return_value = "check-999"
        mock_files.return_value = ["auth/jwt.py"]

        payload = {
            "action": "opened",
            "pull_request": {
                "number": 42,
                "head": {"sha": "abc123"},
            },
            "repository": {
                "full_name": "myorg/auth",
                "name": "auth",
            },
        }
        resp = client.post(
            "/webhook/github",
            json=payload,
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["check_run_id"] == "check-999"
        assert data["files_queued"] == 1

    def test_invalid_signature_rejected(self, client):
        import os
        os.environ["LSIG_GITHUB_WEBHOOK_SECRET"] = "test-secret"
        resp = client.post(
            "/webhook/github",
            content=b'{"action": "opened"}',
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=badhash",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 401
        del os.environ["LSIG_GITHUB_WEBHOOK_SECRET"]


# ─── Certificate API tests ────────────────────────────────────────────────────

class TestCertificateAPI:

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from layer6.certificate_api import app
        return TestClient(app)

    @patch("layer6.certificate_api._store_certificate")
    @patch("layer6.certificate_api.generate_certificate")
    def test_generate_endpoint(self, mock_gen, mock_store, client):
        from layer6.certificate_engine import (
            ChangeImpactCertificate, BlastRadius, SecurityDelta
        )
        mock_cert = ChangeImpactCertificate(
            certificate_id="lsig-cert-PR-99-1234567890",
            pr_id="github:myorg/auth:PR-99",
            service="auth",
            generated_at="2025-01-15T10:00:00+00:00",
            generation_duration_ms=12345,
            changed_functions=[],
            blast_radius=BlastRadius([], [], [], []),
            security_delta=SecurityDelta([], [], [], [], "UNCHANGED"),
            narrative="No risk changes detected.",
            risk_level="NONE",
            signature="abc123def456",
        )
        mock_gen.return_value = mock_cert

        resp = client.post("/certificate/generate", json={
            "pr_id": "github:myorg/auth:PR-99",
            "changed_files": ["auth/jwt.py"],
            "service": "auth",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "NONE"
        assert data["certificate_id"] == "lsig-cert-PR-99-1234567890"
        mock_store.assert_called_once()

    @patch("layer6.certificate_api.run_query")
    def test_get_certificate_not_found(self, mock_run_query, client):
        mock_run_query.return_value = []
        resp = client.get("/certificate/nonexistent-id")
        assert resp.status_code == 404

    @patch("layer6.certificate_api.run_query")
    def test_get_certificate_found(self, mock_run_query, client):
        payload = json.dumps({
            "certificate_id": "cert-123",
            "risk_level": "LOW",
            "pr_id": "PR-1",
        })
        mock_run_query.return_value = [{"payload": payload}]
        resp = client.get("/certificate/cert-123")
        assert resp.status_code == 200
        assert resp.json()["risk_level"] == "LOW"

    def test_verify_endpoint_valid(self, client):
        from layer6.certificate_engine import _sign_certificate
        cert = {"certificate_id": "x", "risk_level": "HIGH", "pr_id": "PR-1"}
        cert["signature"] = _sign_certificate(cert)
        resp = client.post("/certificate/verify", json={"certificate": cert})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_verify_endpoint_invalid(self, client):
        cert = {"certificate_id": "x", "risk_level": "HIGH", "signature": "bad"}
        resp = client.post("/certificate/verify", json={"certificate": cert})
        assert resp.status_code == 200
        assert resp.json()["valid"] is False


# ─── Acceptance criteria summary test ─────────────────────────────────────────

class TestLayer6AcceptanceCriteria:

    @patch("layer6.certificate_engine.get_vm_client")
    @patch("layer6.certificate_engine._generate_narrative")
    @patch("layer6.certificate_engine.run_query")
    def test_full_certificate_round_trip(self, mock_run_query, mock_narrative, mock_vm):
        """
        AC-L6: Full round-trip — generate, sign, verify.
        Certificate must have all sections, correct risk level, valid signature.
        """
        mock_run_query.side_effect = [
            MOCK_FN_ROWS,
            MOCK_BLAST_ROWS,
            MOCK_VULN_ROWS,
            MOCK_PII_ROWS,
        ]
        mock_narrative.return_value = (
            "PR #42 modifies JWT validation. CVE-2023-9999 (KEV-confirmed) "
            "is reachable from the login endpoint. Immediate review required."
        )
        mock_vm.return_value = MagicMock()

        from layer6.certificate_engine import generate_certificate, verify_certificate
        cert = generate_certificate(
            pr_id="github:myorg/auth:PR-42",
            changed_files=["auth/jwt.py"],
            service="auth",
        )

        # AC-L6-1: < 60s
        assert cert.generation_duration_ms < 60_000

        # AC-L6-2: All sections populated
        assert len(cert.changed_functions) >= 1
        assert cert.blast_radius.affected_services
        assert cert.security_delta.new_critical_vulns
        assert cert.narrative

        # AC-L6-3: Signature valid
        cert_dict = asdict(cert)
        assert verify_certificate(cert_dict) is True

        # AC-L6-4: Risk level = CRITICAL (KEV CVE)
        assert cert.risk_level == "CRITICAL"

        # AC-L6-6: Certificate ID set
        assert cert.certificate_id.startswith("lsig-cert-")
