"""
Layer 6 — GitHub Webhook Receiver.

Listens for GitHub `pull_request` webhook events (opened, synchronize, reopened)
and triggers Change Impact Certificate generation. Updates the GitHub Checks API
with real-time status and the final certificate summary.

Security:
  - HMAC-SHA256 webhook signature validation (X-Hub-Signature-256 header)
  - LSIG_GITHUB_WEBHOOK_SECRET environment variable

GitHub Checks lifecycle:
  1. PR opened  → create Check Run (status=in_progress)
  2. Certificate generated → update Check Run (status=completed, conclusion=success/failure)
  3. Certificate JSON posted as Check Run output text (truncated to 65KB GitHub limit)

Usage:
    uvicorn layer6.github_webhook:app --port 8006
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from layer6.certificate_engine import generate_certificate, ChangeImpactCertificate
from dataclasses import asdict

logger = logging.getLogger(__name__)

app = FastAPI(title="LSIG GitHub Webhook", version="1.0")

# ─── Config ───────────────────────────────────────────────────────────────────

def _webhook_secret() -> bytes:
    return os.environ.get("LSIG_GITHUB_WEBHOOK_SECRET", "").encode()


def _github_token() -> str:
    return os.environ.get("LSIG_GITHUB_TOKEN", "")


def _service_map() -> dict[str, str]:
    """Load repo→service mapping from env. Format: LSIG_SERVICE_MAP=repo1:svc1,repo2:svc2"""
    raw = os.environ.get("LSIG_SERVICE_MAP", "")
    result = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" in pair:
            repo, svc = pair.split(":", 1)
            result[repo.strip()] = svc.strip()
    return result


# ─── GitHub API client ────────────────────────────────────────────────────────

def _gh_request(method: str, url: str, body: dict | None = None) -> dict:
    token = _github_token()
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("GitHub API error %s %s: %s", method, url, e)
        return {}


def _create_check_run(
    repo_full_name: str,
    head_sha: str,
    pr_number: int,
) -> str | None:
    """Create a GitHub Check Run and return its ID."""
    url = f"https://api.github.com/repos/{repo_full_name}/check-runs"
    result = _gh_request("POST", url, {
        "name": "LSIG Change Impact",
        "head_sha": head_sha,
        "status": "in_progress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "output": {
            "title": "Analysing change impact…",
            "summary": f"Generating certificate for PR #{pr_number}. This takes up to 60s.",
        },
    })
    check_id = result.get("id")
    if check_id:
        logger.info("Created check run %s for %s@%s", check_id, repo_full_name, head_sha[:8])
    return str(check_id) if check_id else None


def _update_check_run(
    repo_full_name: str,
    check_run_id: str,
    cert: ChangeImpactCertificate,
) -> None:
    """Update the Check Run with the completed certificate."""
    url = f"https://api.github.com/repos/{repo_full_name}/check-runs/{check_run_id}"

    risk_to_conclusion = {
        "CRITICAL": "failure",
        "HIGH": "failure",
        "MEDIUM": "neutral",
        "LOW": "success",
        "NONE": "success",
    }
    conclusion = risk_to_conclusion.get(cert.risk_level, "neutral")

    # Build summary (GitHub limits output.text to 65536 bytes)
    cert_json = json.dumps(asdict(cert), indent=2, default=str)
    if len(cert_json.encode()) > 60000:
        cert_json = cert_json[:60000] + "\n... (truncated)"

    title = f"Risk: {cert.risk_level} — {len(cert.changed_functions)} function(s) changed"

    _gh_request("PATCH", url, {
        "status": "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": cert.narrative,
            "text": f"```json\n{cert_json}\n```",
        },
    })
    logger.info("Updated check run %s conclusion=%s", check_run_id, conclusion)


def _post_pr_comment(
    repo_full_name: str,
    pr_number: int,
    cert: ChangeImpactCertificate,
) -> None:
    """Post a summary comment on the PR."""
    risk_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NONE": "✅",
    }.get(cert.risk_level, "⚪")

    body = (
        f"## {risk_emoji} LSIG Change Impact Certificate\n\n"
        f"**Risk Level:** {cert.risk_level}  \n"
        f"**Certificate ID:** `{cert.certificate_id}`  \n"
        f"**Generated in:** {cert.generation_duration_ms}ms\n\n"
        f"### Summary\n{cert.narrative}\n\n"
        f"### Impact\n"
        f"- **Functions changed:** {len(cert.changed_functions)}\n"
        f"- **Blast radius:** {len(cert.blast_radius.transitive_callers)} callers, "
        f"{len(cert.blast_radius.affected_endpoints)} endpoints\n"
        f"- **Critical CVEs in scope:** {len(cert.security_delta.new_critical_vulns)}\n"
        f"- **PII flows affected:** {len(cert.security_delta.pii_flows_added)}\n\n"
        f"<details><summary>Full certificate JSON</summary>\n\n"
        f"```json\n{json.dumps(asdict(cert), indent=2, default=str)[:8000]}\n```\n"
        f"</details>\n\n"
        f"*[LSIG](https://github.com/lsig) · "
        f"[View dashboard](/service/{cert.service})*"
    )

    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    _gh_request("POST", url, {"body": body})


# ─── Signature validation ─────────────────────────────────────────────────────

def _verify_github_signature(payload: bytes, signature_header: str | None) -> bool:
    secret = _webhook_secret()
    if not secret:
        return True  # dev mode: no secret configured
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ─── Background certificate job ───────────────────────────────────────────────

def _run_certificate_job(
    repo_full_name: str,
    pr_id: str,
    pr_number: int,
    head_sha: str,
    changed_files: list[str],
    service: str,
    check_run_id: str | None,
) -> None:
    try:
        cert = generate_certificate(
            pr_id=pr_id,
            changed_files=changed_files,
            service=service,
        )
        if check_run_id:
            _update_check_run(repo_full_name, check_run_id, cert)
        _post_pr_comment(repo_full_name, pr_number, cert)
    except Exception as e:
        logger.error("Certificate generation failed for %s: %s", pr_id, e)
        if check_run_id:
            _gh_request(
                "PATCH",
                f"https://api.github.com/repos/{repo_full_name}/check-runs/{check_run_id}",
                {
                    "status": "completed",
                    "conclusion": "failure",
                    "output": {
                        "title": "Certificate generation failed",
                        "summary": str(e),
                    },
                },
            )


def _get_pr_changed_files(repo_full_name: str, pr_number: int) -> list[str]:
    """Fetch list of changed file paths from GitHub API."""
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/files?per_page=100"
    result = _gh_request("GET", url)
    if isinstance(result, list):
        return [f.get("filename", "") for f in result if f.get("filename")]
    return []


# ─── Webhook endpoint ─────────────────────────────────────────────────────────

@app.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not _verify_github_signature(payload, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return JSONResponse({"status": "ignored", "event": event})

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = data.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return JSONResponse({"status": "ignored", "action": action})

    pr = data.get("pull_request", {})
    repo = data.get("repository", {})
    repo_full_name = repo.get("full_name", "")
    pr_number = pr.get("number", 0)
    head_sha = pr.get("head", {}).get("sha", "")

    # Derive service from repo name
    service_map = _service_map()
    repo_name = repo.get("name", "")
    service = service_map.get(repo_full_name) or service_map.get(repo_name) or repo_name

    pr_id = f"github:{repo_full_name}:PR-{pr_number}"

    # Create check run immediately (visible to developer within 1s)
    check_run_id = _create_check_run(repo_full_name, head_sha, pr_number)

    # Fetch changed files and run certificate in background
    changed_files = _get_pr_changed_files(repo_full_name, pr_number)

    background_tasks.add_task(
        _run_certificate_job,
        repo_full_name=repo_full_name,
        pr_id=pr_id,
        pr_number=pr_number,
        head_sha=head_sha,
        changed_files=changed_files,
        service=service,
        check_run_id=check_run_id,
    )

    logger.info("Queued certificate job pr=%s service=%s files=%d",
                pr_id, service, len(changed_files))

    return JSONResponse({
        "status": "accepted",
        "pr_id": pr_id,
        "check_run_id": check_run_id,
        "files_queued": len(changed_files),
    })


@app.get("/health")
def health():
    return {"status": "ok"}
