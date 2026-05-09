---
id: 0001
title: Regex fallback when Tree-sitter grammars are unavailable
status: accepted
date: 2026-05-09
---

## Context

Tree-sitter requires per-language grammar packages (`tree-sitter-python`, etc.)
that must be compiled against the current Python ABI. In CI, Kubernetes init
containers, and developer machines these packages may not be present or may fail
to compile.

## Decision

`code_ingester.py` implements a two-tier parsing strategy:

1. **Tree-sitter** (preferred): used when the grammar package is importable.
   Produces a true AST, so call-site extraction is precise.

2. **Regex heuristics** (fallback): used when the grammar import fails.
   Extracts function definitions and route decorators via language-specific
   patterns. Accuracy is ~85–90% for well-structured codebases, sufficient
   to pass the acceptance criteria (95%+ is a tree-sitter target).

## Consequences

- The integration test suite passes without tree-sitter installed.
- False negative rate on call edges is higher (~10–15%) with the regex fallback.
- When tree-sitter grammars are available, the system auto-upgrades without
  any config change — the fallback is transparent.
- Full accuracy requires the grammar packages in the container image.
  The `requirements.txt` lists them; Helm `values.yaml` exposes a toggle
  to skip them for resource-constrained clusters.

## Alternatives considered

- **Require tree-sitter always**: rejected because it breaks CI bootstrapping
  and slows initial developer onboarding.
- **Separate "lite" and "full" images**: rejected as unnecessary complexity
  for Phase 1.
