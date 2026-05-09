"""
Layer 3 — SBOM Ingestion Pipeline.

For each service container image:
  1. Runs Syft to produce a CycloneDX JSON SBOM.
  2. Parses each component and upserts it as a Dependency node in Neo4j.
  3. Archives the raw SBOM artifact to MinIO.

Triggered:
  - Automatically on every CI build via the webhook receiver (Layer 6).
  - Manually: python -m layer3.sbom_ingester --image <image> --service <name>

Incremental: skips re-ingestion if the image digest hasn't changed since last run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from layer1.neo4j_client import run_query, upsert_node
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── MinIO client (optional — degrades gracefully if not configured) ──────────

def _minio_client():
    try:
        from minio import Minio
        endpoint = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
        access_key = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
        secret_key = os.environ.get("MINIO_SECRET_KEY", "minioadmin")
        secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"
        return Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
    except ImportError:
        logger.warning("minio package not installed — SBOM archival disabled")
        return None


MINIO_BUCKET = "lsig-sboms"


def _archive_sbom(service: str, image_digest: str, sbom_path: Path) -> str | None:
    """Upload SBOM JSON to MinIO. Returns the object key or None on failure."""
    client = _minio_client()
    if client is None:
        return None

    object_key = f"{service}/{image_digest}/sbom.cyclonedx.json"
    try:
        # Ensure bucket exists
        if not client.bucket_exists(MINIO_BUCKET):
            client.make_bucket(MINIO_BUCKET)

        client.fput_object(
            MINIO_BUCKET, object_key, str(sbom_path),
            content_type="application/vnd.cyclonedx+json",
        )
        logger.info("SBOM archived → minio://%s/%s", MINIO_BUCKET, object_key)
        return object_key
    except Exception as e:
        logger.warning("SBOM archival failed: %s", e)
        return None


# ─── Syft runner ──────────────────────────────────────────────────────────────

def _syft_available() -> bool:
    try:
        subprocess.run(["syft", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def run_syft(image_ref: str, output_path: Path) -> None:
    """
    Run Syft against an image reference and write CycloneDX JSON to output_path.
    image_ref can be:
      - docker image name: "myapp:latest"
      - OCI tarball:       "docker-archive:/path/to/image.tar"
      - directory:         "dir:/path/to/dir"
    """
    if not _syft_available():
        raise RuntimeError(
            "syft not found in PATH. Install from https://github.com/anchore/syft"
        )

    cmd = [
        "syft", image_ref,
        "--output", f"cyclonedx-json={output_path}",
        "--quiet",
    ]
    logger.info("Running Syft: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Syft failed (exit {result.returncode}): {result.stderr[:500]}"
        )


# ─── CycloneDX parser ─────────────────────────────────────────────────────────

@dataclass
class Component:
    name: str
    version: str
    ecosystem: str      # "pypi" | "npm" | "go" | "maven" | "gem" | "cargo" | "unknown"
    purl: str           # package URL
    cpe: str            # CPE 2.3 string (for CVE matching)
    licenses: list[str]


# purl ecosystem prefix → canonical ecosystem name
_PURL_ECOSYSTEM: dict[str, str] = {
    "pkg:pypi": "pypi",
    "pkg:npm": "npm",
    "pkg:golang": "go",
    "pkg:maven": "maven",
    "pkg:gem": "gem",
    "pkg:cargo": "cargo",
    "pkg:nuget": "nuget",
    "pkg:composer": "composer",
    "pkg:deb": "deb",
    "pkg:rpm": "rpm",
    "pkg:apk": "apk",
}


def _ecosystem_from_purl(purl: str) -> str:
    for prefix, name in _PURL_ECOSYSTEM.items():
        if purl.startswith(prefix):
            return name
    return "unknown"


def parse_cyclonedx(sbom_path: Path) -> list[Component]:
    """Parse a CycloneDX JSON SBOM and return a list of Component objects."""
    data: dict = json.loads(sbom_path.read_text())
    components = data.get("components", [])
    result: list[Component] = []

    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        ecosystem = _ecosystem_from_purl(purl)

        # CPE — may be a string or list; take first
        cpes = comp.get("cpe", "") or ""
        if isinstance(cpes, list):
            cpe = cpes[0] if cpes else ""
        else:
            cpe = cpes

        licenses = [
            lic.get("id", lic.get("name", ""))
            for lic in comp.get("licenses", [])
            if isinstance(lic, dict)
        ]

        if name and version:
            result.append(Component(
                name=name, version=version, ecosystem=ecosystem,
                purl=purl, cpe=cpe, licenses=licenses,
            ))

    return result


# ─── Dependency node ID ───────────────────────────────────────────────────────

def _dep_id(service: str, ecosystem: str, name: str, version: str) -> str:
    return f"{service}:{ecosystem}:{name}:{version}"


# ─── Neo4j ingestion ──────────────────────────────────────────────────────────

def ingest_components(service: str, components: list[Component]) -> int:
    """Upsert Dependency nodes and link them to the Service node. Returns count."""
    upsert_node("Service", id_props={"id": service}, extra_props={"name": service})

    for comp in components:
        dep_id = _dep_id(service, comp.ecosystem, comp.name, comp.version)
        upsert_node(
            "Dependency",
            id_props={"id": dep_id},
            extra_props={
                "name": comp.name,
                "version": comp.version,
                "ecosystem": comp.ecosystem,
                "purl": comp.purl,
                "cpe": comp.cpe,
                "service": service,
                "licenses": comp.licenses,
            },
        )
        # Link Module → Dependency (best-effort; Module nodes created by Layer 1)
        run_query(
            """
            MATCH (s:Service {id: $svc})
            MATCH (d:Dependency {id: $dep_id})
            MERGE (s)-[:USES_DEPENDENCY]->(d)
            """,
            {"svc": service, "dep_id": dep_id},
        )

    logger.info("Upserted %d Dependency nodes for service=%s", len(components), service)
    return len(components)


# ─── Incremental state ────────────────────────────────────────────────────────

def _image_digest(image_ref: str) -> str:
    """Return a stable digest for the image reference."""
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", image_ref],
            stderr=subprocess.DEVNULL,
        )
        digest = out.decode().strip()
        if digest:
            return hashlib.sha256(digest.encode()).hexdigest()[:16]
    except Exception:
        pass
    # Fallback: hash the image ref + current date (day-level granularity)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return hashlib.sha256(f"{image_ref}:{today}".encode()).hexdigest()[:16]


def _state_key(service: str) -> str:
    return f"sbom:{service}"


def _last_digest(service: str) -> str | None:
    rows = run_query(
        "MATCH (s:Service {id: $svc}) RETURN s.last_sbom_digest AS d",
        {"svc": service},
    )
    return rows[0]["d"] if rows and rows[0]["d"] else None


def _save_digest(service: str, digest: str) -> None:
    run_query(
        "MATCH (s:Service {id: $svc}) SET s.last_sbom_digest = $digest",
        {"svc": service, "digest": digest},
    )


# ─── Main entry point ─────────────────────────────────────────────────────────

def ingest(
    image_ref: str,
    service: str,
    force: bool = False,
) -> dict:
    """
    Run the full SBOM ingestion pipeline for an image.

    Returns a summary dict.
    """
    digest = _image_digest(image_ref)
    last = _last_digest(service)

    if last == digest and not force:
        logger.info("Image digest unchanged (%s) — skipping SBOM re-ingestion", digest)
        return {"status": "no_changes", "service": service, "digest": digest}

    with tempfile.TemporaryDirectory() as tmpdir:
        sbom_path = Path(tmpdir) / "sbom.cyclonedx.json"

        with_retry(
            lambda: run_syft(image_ref, sbom_path),
            label=f"syft:{service}",
            max_attempts=3,
        )

        components = parse_cyclonedx(sbom_path)
        count = ingest_components(service, components)
        _archive_sbom(service, digest, sbom_path)

    # Ensure Service node exists before saving digest
    upsert_node("Service", id_props={"id": service}, extra_props={"name": service})
    _save_digest(service, digest)

    summary = {
        "status": "ok",
        "service": service,
        "image": image_ref,
        "digest": digest,
        "components_ingested": count,
    }
    logger.info("SBOM ingest complete: %s", summary)
    return summary


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSIG Layer 3 — SBOM Ingester")
    parser.add_argument("--image", required=True, help="Container image reference")
    parser.add_argument("--service", required=True, help="Logical service name")
    parser.add_argument("--force", action="store_true", help="Ignore incremental state")
    args = parser.parse_args()
    result = ingest(args.image, args.service, force=args.force)
    print(json.dumps(result, indent=2))
