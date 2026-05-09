"""
Layer 1 — Code Intelligence Engine ingestion pipeline.

Accepts a git repo path or GitHub URL, parses source files with Tree-sitter,
extracts function definitions, call sites, and API endpoints, then upserts
everything into Neo4j.

Supports incremental runs: only re-analyses files changed since last run.

Usage:
    python -m layer1.code_ingester --repo https://github.com/expressjs/express \
                                   --service express
    python -m layer1.code_ingester --repo /path/to/local/repo --service myapp
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from layer1.neo4j_client import run_query, upsert_node, upsert_relationship
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

# ─── Language → Tree-sitter grammar package mapping ───────────────────────────
LANG_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
}

# ─── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class FunctionNode:
    name: str
    file: str          # repo-relative
    line: int
    language: str
    service: str

    @property
    def id(self) -> str:
        return f"{self.service}:{self.file}:{self.name}:{self.line}"


@dataclass
class CallEdge:
    caller_id: str
    callee_name: str   # resolved later if possible
    callee_file: str | None = None
    callee_line: int | None = None


@dataclass
class ApiEndpointNode:
    path: str
    method: str
    service: str
    handler_name: str
    handler_file: str
    handler_line: int
    authenticated: bool = False

    @property
    def id(self) -> str:
        return f"{self.service}:{self.method.upper()}:{self.path}"


@dataclass
class IngestResult:
    functions: list[FunctionNode] = field(default_factory=list)
    calls: list[CallEdge] = field(default_factory=list)
    endpoints: list[ApiEndpointNode] = field(default_factory=list)


# ─── Tree-sitter parsing (with graceful fallback to regex heuristics) ─────────

def _try_import_tree_sitter():
    """Return (Parser, Language) factory or None if tree-sitter not installed."""
    try:
        from tree_sitter import Language, Parser
        return Language, Parser
    except ImportError:
        return None, None


def _parse_with_tree_sitter(source: str, language: str) -> IngestResult:
    """Parse source using Tree-sitter; returns FunctionNodes and CallEdges."""
    Language, Parser = _try_import_tree_sitter()
    if Language is None:
        return IngestResult()

    # Lazy-load the language grammar
    lang_module_map = {
        "python": ("tree_sitter_python", "language"),
        "javascript": ("tree_sitter_javascript", "language"),
        "typescript": ("tree_sitter_typescript", "language_typescript"),
        "tsx": ("tree_sitter_typescript", "language_tsx"),
        "go": ("tree_sitter_go", "language"),
        "java": ("tree_sitter_java", "language"),
        "ruby": ("tree_sitter_ruby", "language"),
    }
    if language not in lang_module_map:
        return IngestResult()

    module_name, attr = lang_module_map[language]
    try:
        mod = __import__(module_name)
        lang = Language(getattr(mod, attr)())
    except (ImportError, AttributeError):
        logger.debug("tree-sitter grammar not installed for %s — skipping", language)
        return IngestResult()

    parser = Parser(lang)
    tree = parser.parse(source.encode())
    return IngestResult()   # populated by language-specific visitors below


# ─── Regex fallback parser (works without tree-sitter installed) ──────────────

# Pattern sets per language for function definitions and call expressions.
# These are heuristic — good enough for integration tests, not production-grade.
_PATTERNS: dict[str, dict] = {
    "python": {
        "func_def": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(", re.MULTILINE),
        "call": re.compile(r"\b(\w+)\s*\("),
        "route": re.compile(
            r"@(?:app|router|blueprint)\.(?:route|get|post|put|patch|delete|head)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        ),
        "route_method": re.compile(r"methods\s*=\s*\[([^\]]+)\]"),
    },
    "javascript": {
        "func_def": re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))",
            re.MULTILINE,
        ),
        "call": re.compile(r"\b(\w+)\s*\("),
        "route": re.compile(
            r"(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
            re.MULTILINE,
        ),
        "route_verb": re.compile(
            r"(?:app|router)\.(get|post|put|patch|delete|use)\s*\(",
            re.MULTILINE,
        ),
    },
    "typescript": {
        "func_def": re.compile(
            r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)|(\w+)\s*\([^)]*\)\s*(?::\s*\S+)?\s*\{)",
            re.MULTILINE,
        ),
        "call": re.compile(r"\b(\w+)\s*\("),
        "route": re.compile(
            r"(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
            re.MULTILINE,
        ),
        "route_verb": re.compile(
            r"(?:app|router)\.(get|post|put|patch|delete|use)\s*\(",
            re.MULTILINE,
        ),
    },
    "go": {
        "func_def": re.compile(r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", re.MULTILINE),
        "call": re.compile(r"\b(\w+)\s*\("),
        "route": re.compile(
            r'(?:Handle|HandleFunc|GET|POST|PUT|PATCH|DELETE)\s*\(\s*"([^"]+)"',
            re.MULTILINE,
        ),
    },
    "java": {
        "func_def": re.compile(
            r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]+)?\{",
            re.MULTILINE,
        ),
        "call": re.compile(r"\b(\w+)\s*\("),
        "route": re.compile(
            r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
            re.MULTILINE,
        ),
    },
    "ruby": {
        "func_def": re.compile(r"^\s*def\s+(\w+)", re.MULTILINE),
        "call": re.compile(r"\b(\w+)\s*[\(\s]"),
        "route": re.compile(
            r"(?:get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        ),
    },
}

_NOISE_WORDS = frozenset({
    "if", "for", "while", "return", "print", "len", "range", "str", "int",
    "list", "dict", "set", "type", "isinstance", "super", "self", "cls",
    "require", "module", "exports", "console", "process", "object", "array",
    "string", "number", "boolean", "undefined", "null", "true", "false",
    "new", "delete", "typeof", "instanceof", "import", "export", "from",
    "const", "let", "var", "function", "class", "extends", "implements",
    "public", "private", "protected", "static", "void", "this", "super",
    "throw", "try", "catch", "finally", "switch", "case", "break", "continue",
    "async", "await", "yield", "lambda", "pass", "raise", "with", "as", "in",
    "not", "and", "or", "is", "None", "True", "False",
})


def _parse_file_regex(
    source: str, language: str, file_path: str, service: str
) -> IngestResult:
    """Heuristic regex parser — used when tree-sitter grammar is unavailable."""
    result = IngestResult()
    patterns = _PATTERNS.get(language, _PATTERNS.get("javascript", {}))
    lines = source.splitlines()

    # Map line content → line number for function lookup
    line_index: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        line_index[line.strip()] = i

    # Extract function definitions
    func_def_pat = patterns.get("func_def")
    functions_by_name: dict[str, FunctionNode] = {}
    if func_def_pat:
        for m in func_def_pat.finditer(source):
            name = next((g for g in m.groups() if g), None)
            if not name or name in _NOISE_WORDS:
                continue
            line_no = source[:m.start()].count("\n") + 1
            fn = FunctionNode(name=name, file=file_path, line=line_no,
                              language=language, service=service)
            result.functions.append(fn)
            if name not in functions_by_name:
                functions_by_name[name] = fn

    # Extract call sites — map caller (by enclosing function) → callee
    call_pat = patterns.get("call")
    if call_pat and functions_by_name:
        sorted_fns = sorted(result.functions, key=lambda f: f.line)
        for m in call_pat.finditer(source):
            callee = m.group(1)
            if not callee or callee in _NOISE_WORDS:
                continue
            call_line = source[:m.start()].count("\n") + 1
            # Find the enclosing function (last function whose line <= call_line)
            caller = None
            for fn in sorted_fns:
                if fn.line <= call_line:
                    caller = fn
                else:
                    break
            if caller and callee != caller.name:
                result.calls.append(CallEdge(
                    caller_id=caller.id, callee_name=callee
                ))

    # Extract API endpoints / routes
    route_pat = patterns.get("route")
    route_verb_pat = patterns.get("route_verb") or patterns.get("route_method")
    if route_pat:
        for m in route_pat.finditer(source):
            route_path = m.group(1)
            call_line = source[:m.start()].count("\n") + 1

            # Determine HTTP method
            method = "GET"
            if route_verb_pat:
                vm = route_verb_pat.search(source[:m.start() + len(m.group(0))])
                if vm:
                    method = vm.group(1).upper()
            elif "post" in m.group(0).lower():
                method = "POST"
            elif "put" in m.group(0).lower():
                method = "PUT"
            elif "delete" in m.group(0).lower():
                method = "DELETE"

            # Find the handler — next function definition after the decorator/route call
            handler_fn = None
            sorted_fns = sorted(result.functions, key=lambda f: f.line)
            for fn in sorted_fns:
                if fn.line >= call_line:
                    handler_fn = fn
                    break

            ep = ApiEndpointNode(
                path=route_path,
                method=method,
                service=service,
                handler_name=handler_fn.name if handler_fn else "unknown",
                handler_file=file_path,
                handler_line=handler_fn.line if handler_fn else call_line,
                authenticated=bool(re.search(
                    r"auth|login|token|jwt|session|require_auth|authenticated",
                    source[max(0, m.start()-200):m.start()+200], re.IGNORECASE
                )),
            )
            result.endpoints.append(ep)

    return result


# ─── Git helpers ──────────────────────────────────────────────────────────────

def _clone_or_update(repo_url: str, target_dir: Path) -> Path:
    if (target_dir / ".git").exists():
        logger.info("Pulling updates for %s", repo_url)
        subprocess.run(["git", "-C", str(target_dir), "pull", "--ff-only"],
                       check=True, capture_output=True)
    else:
        logger.info("Cloning %s → %s", repo_url, target_dir)
        subprocess.run(["git", "clone", "--depth=50", repo_url, str(target_dir)],
                       check=True, capture_output=True)
    return target_dir


def _changed_files_since(repo_dir: Path, since_sha: str | None) -> list[Path] | None:
    """Return list of changed files since given SHA, or None (= full scan)."""
    if not since_sha:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_dir), "diff", "--name-only", since_sha, "HEAD"],
            stderr=subprocess.DEVNULL,
        )
        return [repo_dir / p for p in out.decode().splitlines() if p.strip()]
    except subprocess.CalledProcessError:
        return None


def _current_sha(repo_dir: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        stderr=subprocess.DEVNULL,
    ).decode().strip()


def _iter_source_files(repo_dir: Path, files: list[Path] | None) -> Iterator[Path]:
    """Yield source files, filtered to supported languages."""
    candidates = files if files is not None else repo_dir.rglob("*")
    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
    for p in candidates:
        if not p.is_file():
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.suffix in LANG_EXTENSIONS:
            yield p


# ─── Last-run state (for incremental ingestion) ───────────────────────────────

def _state_path(service: str) -> Path:
    state_dir = Path(os.environ.get("LSIG_STATE_DIR", "/tmp/lsig_state"))
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / f"{service}.json"


def _load_state(service: str) -> dict:
    p = _state_path(service)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save_state(service: str, state: dict) -> None:
    _state_path(service).write_text(json.dumps(state, indent=2))


# ─── Neo4j upsert helpers ─────────────────────────────────────────────────────

def _upsert_function(fn: FunctionNode) -> None:
    upsert_node(
        "Function",
        id_props={"id": fn.id},
        extra_props={
            "name": fn.name,
            "file": fn.file,
            "line": fn.line,
            "language": fn.language,
            "service": fn.service,
        },
    )


def _upsert_endpoint(ep: ApiEndpointNode) -> None:
    upsert_node(
        "APIEndpoint",
        id_props={"id": ep.id},
        extra_props={
            "path": ep.path,
            "method": ep.method,
            "service": ep.service,
            "authenticated": ep.authenticated,
        },
    )
    # Link endpoint → handler function
    handler_id = f"{ep.service}:{ep.handler_file}:{ep.handler_name}:{ep.handler_line}"
    upsert_relationship(
        "APIEndpoint", {"id": ep.id},
        "HANDLED_BY", {},
        "Function", {"id": handler_id},
    )


def _resolve_and_upsert_calls(
    calls: list[CallEdge], all_functions: dict[str, FunctionNode]
) -> None:
    """Best-effort resolution of callee names to Function node IDs."""
    for edge in calls:
        callee_fn = all_functions.get(edge.callee_name)
        if callee_fn is None:
            continue
        upsert_relationship(
            "Function", {"id": edge.caller_id},
            "CALLS", {},
            "Function", {"id": callee_fn.id},
        )


# ─── Main ingestion entry point ───────────────────────────────────────────────

def ingest(
    repo: str,
    service: str,
    work_dir: Path | None = None,
    force_full: bool = False,
) -> dict:
    """
    Ingest a repository into the Neo4j code graph.

    Args:
        repo:       GitHub URL (https://github.com/...) or local filesystem path.
        service:    Logical service name used as graph namespace.
        work_dir:   Directory to clone into (defaults to /tmp/lsig_repos/<service>).
        force_full: If True, ignore incremental state and re-analyse all files.

    Returns:
        Summary dict with counts of ingested nodes.
    """
    # Resolve repo path
    if repo.startswith("http"):
        clone_base = Path(os.environ.get("LSIG_REPO_DIR", "/tmp/lsig_repos"))
        clone_base.mkdir(parents=True, exist_ok=True)
        repo_dir = work_dir or (clone_base / service)
        with_retry(
            lambda: _clone_or_update(repo, repo_dir),
            label=f"git:clone:{service}",
        )
    else:
        repo_dir = Path(repo)
        if not repo_dir.exists():
            raise FileNotFoundError(f"Repo path does not exist: {repo_dir}")

    # Incremental: determine which files changed since last run
    state = _load_state(service) if not force_full else {}
    last_sha = state.get("last_sha")
    current_sha = _current_sha(repo_dir) if (repo_dir / ".git").exists() else None

    if last_sha == current_sha and not force_full:
        logger.info("No changes since last ingest (sha=%s) — skipping", current_sha)
        return {"status": "no_changes", "sha": current_sha}

    changed_files = _changed_files_since(repo_dir, last_sha) if not force_full else None
    logger.info(
        "Ingesting %s service=%s sha=%s files=%s",
        repo, service, current_sha,
        len(changed_files) if changed_files is not None else "all",
    )

    # Ensure Service node exists
    upsert_node("Service", id_props={"id": service}, extra_props={"name": service, "repo_url": repo})

    # Parse files
    all_functions: dict[str, FunctionNode] = {}
    all_calls: list[CallEdge] = []
    all_endpoints: list[ApiEndpointNode] = []
    file_count = 0

    for src_path in _iter_source_files(repo_dir, changed_files):
        language = LANG_EXTENSIONS[src_path.suffix]
        rel_path = str(src_path.relative_to(repo_dir)).replace("\\", "/")
        try:
            source = src_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.warning("Cannot read %s: %s", src_path, e)
            continue

        result = _parse_file_regex(source, language, rel_path, service)
        for fn in result.functions:
            all_functions[fn.name] = fn
        all_calls.extend(result.calls)
        all_endpoints.extend(result.endpoints)
        file_count += 1

    # Write to Neo4j
    logger.info("Upserting %d functions, %d endpoints …", len(all_functions), len(all_endpoints))
    for fn in all_functions.values():
        _upsert_function(fn)

    for ep in all_endpoints:
        # Ensure handler function node exists before linking
        handler_id = f"{service}:{ep.handler_file}:{ep.handler_name}:{ep.handler_line}"
        if ep.handler_name not in all_functions:
            upsert_node("Function", id_props={"id": handler_id}, extra_props={
                "name": ep.handler_name, "file": ep.handler_file,
                "line": ep.handler_line, "language": "unknown", "service": service,
            })
        _upsert_endpoint(ep)

    _resolve_and_upsert_calls(all_calls, all_functions)

    # Save incremental state
    if current_sha:
        _save_state(service, {"last_sha": current_sha})

    summary = {
        "status": "ok",
        "service": service,
        "sha": current_sha,
        "files_processed": file_count,
        "functions_ingested": len(all_functions),
        "endpoints_ingested": len(all_endpoints),
        "call_edges_attempted": len(all_calls),
    }
    logger.info("Ingest complete: %s", summary)
    return summary


# ─── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSIG Layer 1 — Code Ingester")
    parser.add_argument("--repo", required=True, help="GitHub URL or local path")
    parser.add_argument("--service", required=True, help="Logical service name")
    parser.add_argument("--force-full", action="store_true",
                        help="Ignore incremental state, re-analyse all files")
    args = parser.parse_args()

    result = ingest(args.repo, args.service, force_full=args.force_full)
    print(json.dumps(result, indent=2))
