"""
Layer 4 — Ownership Ingester.

Derives code ownership from two authoritative sources — neither requires
manually maintained YAML (Rule 1):

  1. CODEOWNERS file  — explicit team → path mappings declared in the repo.
  2. git blame        — dominant contributor per file (fallback + validation).

Annotates every Function, Module, and APIEndpoint node with:
  owner_team  — team slug from CODEOWNERS (e.g. "@myorg/platform")
  owner_email — email of the dominant git blame contributor

Re-runs incrementally on every push (only re-annotates changed files).

Usage:
    python -m layer4.ownership_ingester --repo /path/to/repo --service myapp
"""

from __future__ import annotations

import re
import subprocess
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from layer1.neo4j_client import run_query
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── CODEOWNERS parser ────────────────────────────────────────────────────────

@dataclass
class OwnerRule:
    pattern: str        # glob pattern relative to repo root
    owners: list[str]   # list of "@org/team" or "@user" strings
    team: str           # first team owner (best-effort primary)


def _is_team(owner: str) -> bool:
    """Return True if owner string looks like a GitHub team (@org/team)."""
    return "/" in owner


def parse_codeowners(repo_dir: Path) -> list[OwnerRule]:
    """
    Parse CODEOWNERS from standard locations.
    Returns rules in file order — later rules take precedence (GitHub semantics).
    """
    candidates = [
        repo_dir / "CODEOWNERS",
        repo_dir / ".github" / "CODEOWNERS",
        repo_dir / "docs" / "CODEOWNERS",
    ]
    for path in candidates:
        if path.exists():
            return _parse_codeowners_file(path)
    return []


def _parse_codeowners_file(path: Path) -> list[OwnerRule]:
    rules: list[OwnerRule] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern = parts[0]
        owners = parts[1:]
        team = next((o for o in owners if _is_team(o)), owners[0])
        rules.append(OwnerRule(pattern=pattern, owners=owners, team=team))
    return rules


def match_owners(file_path: str, rules: list[OwnerRule]) -> OwnerRule | None:
    """
    Find the last matching CODEOWNERS rule for a file path (GitHub semantics:
    last match wins).
    """
    matched: OwnerRule | None = None
    for rule in rules:
        pattern = rule.pattern
        # CODEOWNERS patterns: leading slash = root-relative, no leading slash = anywhere
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if fnmatch(file_path, pattern) or fnmatch(file_path, f"**/{pattern}"):
            matched = rule
        # Directory patterns (ending with /)
        elif pattern.endswith("/") and file_path.startswith(pattern.rstrip("/")):
            matched = rule
        # Exact prefix match for directory-level rules
        elif "/" not in pattern and fnmatch(Path(file_path).name, pattern):
            matched = rule
    return matched


# ─── git blame contributor analysis ──────────────────────────────────────────

def _git_blame_emails(repo_dir: Path, file_path: str) -> list[str]:
    """
    Return a list of committer email addresses from git blame for a file.
    One entry per line — most-frequent = dominant contributor.
    """
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_dir), "blame", "--line-porcelain", file_path],
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        emails = re.findall(r"^author-mail <(.+?)>$", out.decode(errors="ignore"), re.MULTILINE)
        return emails
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return []


def dominant_contributor(repo_dir: Path, file_path: str) -> str | None:
    """Return the email address of the author responsible for most lines in a file."""
    emails = _git_blame_emails(repo_dir, file_path)
    if not emails:
        return None
    counter = Counter(emails)
    # Ignore bot accounts
    filtered = {e: c for e, c in counter.items()
                if "bot" not in e.lower() and "noreply" not in e.lower()}
    if not filtered:
        return counter.most_common(1)[0][0]
    return max(filtered, key=filtered.get)  # type: ignore[arg-type]


# ─── Neo4j annotation ────────────────────────────────────────────────────────

def _annotate_nodes_for_file(
    service: str,
    file_path: str,  # repo-relative
    owner_team: str,
    owner_email: str | None,
) -> int:
    """Annotate all Function, Module, and APIEndpoint nodes for a given file."""
    params = {
        "svc": service,
        "file": file_path,
        "team": owner_team,
        "email": owner_email or "",
    }

    # Annotate Functions
    run_query(
        """
        MATCH (f:Function {service: $svc, file: $file})
        WHERE f.deprecated_at IS NULL
        SET f.owner_team = $team, f.owner_email = $email
        """,
        params,
    )

    # Annotate Modules
    run_query(
        """
        MATCH (m:Module {service: $svc, path: $file})
        WHERE m.deprecated_at IS NULL
        SET m.owner_team = $team, m.owner_email = $email
        """,
        params,
    )

    # Annotate APIEndpoints (via HANDLED_BY → Function in this file)
    run_query(
        """
        MATCH (ep:APIEndpoint {service: $svc})-[:HANDLED_BY]->(f:Function {file: $file})
        WHERE ep.deprecated_at IS NULL
        SET ep.owner_team = $team, ep.owner_email = $email
        """,
        params,
    )

    return 1


def _files_for_service(service: str) -> list[str]:
    """Return distinct file paths for all Function nodes in a service."""
    rows = run_query(
        """
        MATCH (f:Function {service: $svc})
        WHERE f.deprecated_at IS NULL AND f.file IS NOT NULL
        RETURN DISTINCT f.file AS file
        """,
        {"svc": service},
    )
    return [r["file"] for r in rows]


# ─── Incremental: only process changed files ──────────────────────────────────

def _changed_files_since(repo_dir: Path, since_sha: str | None) -> list[str] | None:
    if not since_sha:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_dir), "diff", "--name-only", since_sha, "HEAD"],
            stderr=subprocess.DEVNULL,
        )
        return [p for p in out.decode().splitlines() if p.strip()]
    except subprocess.CalledProcessError:
        return None


# ─── Main entry point ─────────────────────────────────────────────────────────

def ingest(repo_dir: str | Path, service: str, since_sha: str | None = None) -> dict:
    """
    Annotate all graph nodes for a service with ownership data.

    Args:
        repo_dir:   Path to the cloned repository on disk.
        service:    Logical service name.
        since_sha:  If provided, only re-annotate files changed since this SHA.

    Returns:
        Summary dict with annotation counts.
    """
    repo = Path(repo_dir)
    if not repo.exists():
        raise FileNotFoundError(f"Repo path not found: {repo}")

    codeowners_rules = parse_codeowners(repo)
    logger.info(
        "Loaded %d CODEOWNERS rules for service=%s", len(codeowners_rules), service
    )

    # Determine which files to process
    graph_files = _files_for_service(service)
    if not graph_files:
        return {"status": "no_files", "service": service}

    changed = _changed_files_since(repo, since_sha)
    if changed is not None:
        graph_files = [f for f in graph_files if f in set(changed)]
        logger.info("Incremental mode: %d changed files to re-annotate", len(graph_files))

    annotated = 0
    no_owner = 0

    for file_path in graph_files:
        # Step 1: CODEOWNERS team
        rule = match_owners(file_path, codeowners_rules)
        owner_team = rule.team if rule else ""

        # Step 2: git blame dominant contributor
        email = with_retry(
            lambda fp=file_path: dominant_contributor(repo, fp),
            label=f"gitblame:{file_path}",
            max_attempts=2,
            exceptions=(Exception,),
        )

        if not owner_team and not email:
            no_owner += 1
            continue

        _annotate_nodes_for_file(service, file_path, owner_team, email)
        annotated += 1

    summary = {
        "status": "ok",
        "service": service,
        "files_annotated": annotated,
        "files_without_owner": no_owner,
        "codeowners_rules": len(codeowners_rules),
    }
    logger.info("Ownership ingest complete: %s", summary)
    return summary


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser(description="LSIG Layer 4 — Ownership Ingester")
    parser.add_argument("--repo", required=True, help="Local repo path")
    parser.add_argument("--service", required=True, help="Service name")
    parser.add_argument("--since", help="Annotate only files changed since this SHA")
    args = parser.parse_args()
    print(json.dumps(ingest(args.repo, args.service, args.since), indent=2))
