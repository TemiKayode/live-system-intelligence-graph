"""
Layer 6 — Certificate REST API.

Exposes:
  POST /certificate/generate   — trigger certificate generation synchronously
  GET  /certificate/{cert_id}  — retrieve a stored certificate by ID
  POST /certificate/verify     — verify a certificate signature
  GET  /pr/{pr_id}/certificate — latest certificate for a PR

Port: 8006 (webhook receiver is also on 8006 via the same app)
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from layer6.certificate_engine import (
    generate_certificate,
    verify_certificate,
    ChangeImpactCertificate,
)
from layer1.neo4j_client import run_query

logger = logging.getLogger(__name__)


# ─── Request/response models ──────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    pr_id: str
    changed_files: list[str]
    service: str
    repo_dir: str = ""


class VerifyRequest(BaseModel):
    certificate: dict


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="LSIG Certificate API", version="1.0")


@app.post("/certificate/generate")
def generate(req: GenerateRequest):
    """Synchronously generate a Change Impact Certificate. Target: < 60s."""
    try:
        cert = generate_certificate(
            pr_id=req.pr_id,
            changed_files=req.changed_files,
            service=req.service,
            repo_dir=req.repo_dir,
        )
        cert_dict = asdict(cert)
        _store_certificate(cert_dict)
        return JSONResponse(cert_dict)
    except Exception as e:
        logger.error("Certificate generation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/certificate/{cert_id}")
def get_certificate(cert_id: str):
    """Retrieve a previously generated certificate by ID."""
    rows = run_query(
        """
        MATCH (c:Certificate {id: $cert_id})
        RETURN c.payload AS payload
        """,
        {"cert_id": cert_id},
    )
    if not rows or not rows[0].get("payload"):
        raise HTTPException(status_code=404, detail=f"Certificate {cert_id!r} not found")
    try:
        return JSONResponse(json.loads(rows[0]["payload"]))
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Stored certificate is corrupt")


@app.post("/certificate/verify")
def verify(req: VerifyRequest):
    """Verify the HMAC-SHA256 signature of a certificate."""
    valid = verify_certificate(req.certificate)
    return {"valid": valid, "certificate_id": req.certificate.get("certificate_id")}


@app.get("/pr/{pr_id}/certificate")
def latest_for_pr(pr_id: str):
    """Return the most recent certificate generated for a PR."""
    rows = run_query(
        """
        MATCH (c:Certificate {pr_id: $pr_id})
        RETURN c.payload AS payload, c.generated_at AS generated_at
        ORDER BY c.generated_at DESC
        LIMIT 1
        """,
        {"pr_id": pr_id},
    )
    if not rows or not rows[0].get("payload"):
        raise HTTPException(status_code=404, detail=f"No certificate found for PR {pr_id!r}")
    try:
        return JSONResponse(json.loads(rows[0]["payload"]))
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Stored certificate is corrupt")


@app.get("/health")
def health():
    return {"status": "ok"}


# ─── Storage ──────────────────────────────────────────────────────────────────

def _store_certificate(cert_dict: dict) -> None:
    """Persist certificate JSON to Neo4j as a Certificate node."""
    from layer1.neo4j_client import upsert_node
    upsert_node(
        label="Certificate",
        id_props={"id": cert_dict["certificate_id"]},
        extra_props={
            "pr_id": cert_dict["pr_id"],
            "service": cert_dict["service"],
            "risk_level": cert_dict["risk_level"],
            "generated_at": cert_dict["generated_at"],
            "generation_duration_ms": cert_dict["generation_duration_ms"],
            "payload": json.dumps(cert_dict, default=str),
        },
    )
