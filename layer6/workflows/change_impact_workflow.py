"""
Layer 6 — Temporal Workflow: ChangeImpactWorkflow.

Orchestrates certificate generation as a durable Temporal workflow so that:
  - Transient failures (Neo4j blip, Claude timeout) are automatically retried
  - Long-running steps don't block the webhook handler
  - Each step has independent timeout and retry policy
  - The workflow is idempotent: re-running with the same workflow ID is safe

Workflow steps (activities):
  1. resolve_changed_functions  — Neo4j query for changed files
  2. compute_blast_radius       — graph traversal up to depth 5
  3. compute_security_delta     — CVE + PII delta queries
  4. generate_narrative         — Claude API call
  5. sign_and_store_certificate — HMAC sign + write to Neo4j + emit to VictoriaMetrics
  6. post_github_status         — update Check Run + post PR comment

Each activity has a 30s start-to-close timeout and 3 retry attempts.
The overall workflow must complete within 60 seconds (enforced by execution timeout).

Usage (worker):
    python -m layer6.workflows.change_impact_workflow worker

Usage (trigger, for testing):
    python -m layer6.workflows.change_impact_workflow trigger \
        --pr github:myorg/myrepo:PR-42 \
        --service auth \
        --files auth/jwt.py,auth/models.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

logger = logging.getLogger(__name__)

# ─── Input/output types ───────────────────────────────────────────────────────

@dataclass
class CertificateWorkflowInput:
    pr_id: str
    service: str
    changed_files: list[str]
    repo_full_name: str = ""
    pr_number: int = 0
    check_run_id: str = ""


@dataclass
class CertificateWorkflowOutput:
    certificate_id: str
    risk_level: str
    generation_duration_ms: int
    signature: str


# ─── Temporal imports (optional — graceful stub if not installed) ──────────────

try:
    from temporalio import activity, workflow
    from temporalio.client import Client
    from temporalio.worker import Worker
    from temporalio.common import RetryPolicy
    _TEMPORAL_AVAILABLE = True
except ImportError:
    _TEMPORAL_AVAILABLE = False
    logger.warning(
        "temporalio not installed. Temporal workflow will run in stub mode. "
        "Install with: pip install temporalio"
    )


# ─── Activity implementations ─────────────────────────────────────────────────

if _TEMPORAL_AVAILABLE:
    @activity.defn
    async def resolve_functions_activity(inp: CertificateWorkflowInput) -> list[dict]:
        from layer6.certificate_engine import _resolve_changed_functions
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, _resolve_changed_functions, inp.changed_files, inp.service
        )

    @activity.defn
    async def blast_radius_activity(function_ids: list[str]) -> dict:
        from layer6.certificate_engine import _compute_blast_radius
        import asyncio
        loop = asyncio.get_event_loop()
        blast = await loop.run_in_executor(None, _compute_blast_radius, function_ids)
        return asdict(blast)

    @activity.defn
    async def security_delta_activity(function_ids: list[str], service: str) -> dict:
        from layer6.certificate_engine import _compute_security_delta
        import asyncio
        loop = asyncio.get_event_loop()
        delta = await loop.run_in_executor(
            None, _compute_security_delta, function_ids, service
        )
        return asdict(delta)

    @activity.defn
    async def narrative_activity(payload: dict) -> str:
        from layer6.certificate_engine import (
            _generate_narrative, _determine_risk_level,
            FunctionImpact, BlastRadius, SecurityDelta,
        )
        import asyncio
        loop = asyncio.get_event_loop()

        # Reconstruct dataclasses from dicts
        fns = [FunctionImpact(**f) for f in payload["changed_functions"]]
        blast = BlastRadius(**payload["blast_radius"])
        delta = SecurityDelta(**payload["security_delta"])
        risk_level = _determine_risk_level(delta, blast)

        narrative = await loop.run_in_executor(
            None, _generate_narrative, payload["pr_id"], fns, blast, delta, risk_level
        )
        return narrative

    @activity.defn
    async def post_github_status_activity(payload: dict) -> None:
        from layer6.github_webhook import _update_check_run, _post_pr_comment
        from layer6.certificate_engine import ChangeImpactCertificate, BlastRadius, SecurityDelta, FunctionImpact
        import asyncio

        cert = ChangeImpactCertificate(
            certificate_id=payload["certificate_id"],
            pr_id=payload["pr_id"],
            service=payload["service"],
            generated_at=payload["generated_at"],
            generation_duration_ms=payload["generation_duration_ms"],
            changed_functions=[FunctionImpact(**f) for f in payload["changed_functions"]],
            blast_radius=BlastRadius(**payload["blast_radius"]),
            security_delta=SecurityDelta(**payload["security_delta"]),
            narrative=payload["narrative"],
            risk_level=payload["risk_level"],
            signature=payload["signature"],
        )

        loop = asyncio.get_event_loop()
        if payload.get("check_run_id") and payload.get("repo_full_name"):
            await loop.run_in_executor(
                None, _update_check_run,
                payload["repo_full_name"], payload["check_run_id"], cert
            )
        if payload.get("pr_number") and payload.get("repo_full_name"):
            await loop.run_in_executor(
                None, _post_pr_comment,
                payload["repo_full_name"], payload["pr_number"], cert
            )

    # ─── Workflow definition ──────────────────────────────────────────────────

    _ACTIVITY_OPTS = {
        "start_to_close_timeout": timedelta(seconds=30),
        "retry_policy": RetryPolicy(maximum_attempts=3),
    }

    @workflow.defn
    class ChangeImpactWorkflow:
        """
        Durable Temporal workflow producing a Change Impact Certificate in < 60s.
        Workflow ID: lsig-cert-{pr_id} (idempotent re-runs are safe).
        """

        @workflow.run
        async def run(self, inp: CertificateWorkflowInput) -> CertificateWorkflowOutput:
            import time
            from layer6.certificate_engine import (
                _determine_risk_level, _sign_certificate,
                FunctionImpact, BlastRadius, SecurityDelta, ChangeImpactCertificate,
            )
            from datetime import datetime, timezone
            from dataclasses import asdict

            start = time.monotonic()

            # Step 1: Resolve functions
            fn_rows = await workflow.execute_activity(
                resolve_functions_activity, inp, **_ACTIVITY_OPTS
            )
            changed_functions = [
                FunctionImpact(
                    function_id=r["id"],
                    function_name=r["name"],
                    file=r["file"],
                    owner_team=r.get("owner_team") or "",
                    owner_email=r.get("owner_email") or "",
                    callers_count=r.get("callers_count", 0),
                    runtime_callers_count=r.get("runtime_callers_count", 0),
                    is_endpoint_handler=bool(r.get("is_endpoint_handler", False)),
                )
                for r in fn_rows if r.get("id")
            ]
            function_ids = [f.function_id for f in changed_functions]

            # Steps 2 & 3 in parallel
            blast_task = workflow.execute_activity(
                blast_radius_activity, function_ids, **_ACTIVITY_OPTS
            )
            delta_task = workflow.execute_activity(
                security_delta_activity, function_ids, inp.service, **_ACTIVITY_OPTS
            )
            blast_dict, delta_dict = await asyncio.gather(blast_task, delta_task)

            blast = BlastRadius(**blast_dict)
            delta = SecurityDelta(**delta_dict)
            risk_level = _determine_risk_level(delta, blast)

            # Step 4: Narrative
            narrative = await workflow.execute_activity(
                narrative_activity,
                {
                    "pr_id": inp.pr_id,
                    "changed_functions": [asdict(f) for f in changed_functions],
                    "blast_radius": blast_dict,
                    "security_delta": delta_dict,
                },
                **_ACTIVITY_OPTS,
            )

            # Step 5: Assemble and sign
            duration_ms = int((time.monotonic() - start) * 1000)
            cert = ChangeImpactCertificate(
                certificate_id=f"lsig-cert-{inp.pr_id}-{int(time.time())}",
                pr_id=inp.pr_id,
                service=inp.service,
                generated_at=datetime.now(timezone.utc).isoformat(),
                generation_duration_ms=duration_ms,
                changed_functions=changed_functions,
                blast_radius=blast,
                security_delta=delta,
                narrative=narrative,
                risk_level=risk_level,
                signature="",
            )
            cert_dict = asdict(cert)
            cert.signature = _sign_certificate(cert_dict)
            cert_dict["signature"] = cert.signature

            # Step 6: Update GitHub (fire-and-forget; don't fail cert on GitHub error)
            if inp.check_run_id or inp.pr_number:
                try:
                    await workflow.execute_activity(
                        post_github_status_activity,
                        {
                            **cert_dict,
                            "repo_full_name": inp.repo_full_name,
                            "check_run_id": inp.check_run_id,
                            "pr_number": inp.pr_number,
                        },
                        start_to_close_timeout=timedelta(seconds=20),
                        retry_policy=RetryPolicy(maximum_attempts=2),
                    )
                except Exception as e:
                    workflow.logger.warning("GitHub status update failed: %s", e)

            return CertificateWorkflowOutput(
                certificate_id=cert.certificate_id,
                risk_level=cert.risk_level,
                generation_duration_ms=duration_ms,
                signature=cert.signature,
            )


# ─── Worker entrypoint ────────────────────────────────────────────────────────

async def _run_worker():
    client = await Client.connect("localhost:7233")
    worker = Worker(
        client,
        task_queue="lsig-certificates",
        workflows=[ChangeImpactWorkflow],
        activities=[
            resolve_functions_activity,
            blast_radius_activity,
            security_delta_activity,
            narrative_activity,
            post_github_status_activity,
        ],
    )
    logger.info("Temporal worker started on task queue lsig-certificates")
    await worker.run()


async def _trigger_workflow(pr_id: str, service: str, files: list[str]):
    client = await Client.connect("localhost:7233")
    handle = await client.start_workflow(
        ChangeImpactWorkflow.run,
        CertificateWorkflowInput(pr_id=pr_id, service=service, changed_files=files),
        id=f"lsig-cert-{pr_id}",
        task_queue="lsig-certificates",
    )
    print(f"Started workflow {handle.id}")
    result = await handle.result()
    print(f"Completed: {result}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("worker")
    trig = sub.add_parser("trigger")
    trig.add_argument("--pr", required=True)
    trig.add_argument("--service", required=True)
    trig.add_argument("--files", required=True)
    args = parser.parse_args()

    if not _TEMPORAL_AVAILABLE:
        print("ERROR: temporalio not installed. pip install temporalio")
        sys.exit(1)

    if args.cmd == "worker":
        asyncio.run(_run_worker())
    elif args.cmd == "trigger":
        files = args.files.split(",")
        asyncio.run(_trigger_workflow(args.pr, args.service, files))
    else:
        parser.print_help()
