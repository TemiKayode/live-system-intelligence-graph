---
id: 0004
title: Two-tier PII detection (regex name patterns + Presidio NLP)
status: accepted
date: 2026-05-09
---

## Context

The system must identify PII fields in source code and data schemas without
requiring developers to annotate every field manually. Two properties are required:

1. **Speed**: PII detection runs on every PR (≤60 second budget for the full
   certificate). A slow NLP pass over a large codebase is not acceptable as the
   primary path.

2. **Recall**: Name-only heuristics miss obfuscated or domain-specific names
   ("chd" for cardholder data, "pid" for patient identifier). NLP on surrounding
   context catches these.

## Decision

Implement a **two-tier detection pipeline**:

**Tier 1 — Regex name patterns (always runs)**
A curated set of 14 field-name regexes (email, ssn, credit_card, password, etc.)
covering the most common PII naming conventions. Match in O(n) time with no
ML model loading. Produces zero false negatives for well-named fields.

**Tier 2 — Presidio NLP (runs on tier-1 misses)**
Microsoft Presidio `AnalyzerEngine` with the English NLP pipeline. Analyses:
  - The field name itself
  - ±200 characters of surrounding source context

Presidio is optional: if `presidio-analyzer` is not installed, tier 2 is skipped
and only tier 1 results are returned. This keeps the core pipeline functional in
resource-constrained environments.

**Score threshold**: 0.6 (Presidio default 0.85 is too conservative for short
field-name inputs; 0.6 balances precision/recall on variable-name text).

## Why not CodeQL for PII detection?

CodeQL is precise and semantic, but:
- Requires a full database build (~5–15 minutes per repo).
- Does not have a pre-built "is this a PII field name?" query — it requires
  custom modeling of PII sources per application.
- Produces AST-level results that must be mapped back to field names anyway.

CodeQL is retained for **taint propagation** (tracing PII flow across function
call boundaries), where its interprocedural accuracy is irreplaceable. PII
*identification* (which fields are PII) uses the two-tier approach.

## Regulatory scope derivation

Scope is derived from three ordered evidence sources:

| Priority | Source | Example |
|---|---|---|
| 1 (highest) | Inline annotation `# lsig:regulatory=PCI` | Explicit, developer-controlled |
| 2 | PII field types in graph | CREDIT_CARD → PCI, HEALTH_DATA → HIPAA |
| 3 (lowest) | Service name pattern matching | "payment-svc" → PCI |

The first source that provides evidence wins for confidence label (HIGH/MEDIUM/LOW),
but all sources are unioned for the final scope list. This allows a service named
"user-auth" (LOW confidence GDPR from name) to also get PCI if it has credit card
fields (MEDIUM confidence PCI from PII evidence).

## Consequences

- **False positives**: Name-matching over-fires on generic words ("address" in
  non-PII contexts). Acceptable: over-marking a field as PII causes an audit review,
  which is safe. Under-marking is the dangerous failure mode.
- **False negatives**: Fields named arbitrarily (e.g. `data1`, `value_x`) will not
  be detected by either tier. Mitigated by the taint tracker, which follows data
  flow from labelled PII fields and can mark unlabelled intermediates.
- **Presidio dependency**: Adds ~200MB to the API container (spaCy + models).
  This is accepted. The model is loaded once at startup and cached in memory.
- **CREDENTIAL type**: Passwords, API keys, and tokens are marked as `CREDENTIAL`
  rather than a GDPR/HIPAA type. They drive SOC2 scope and trigger separate
  secret-scanning alerts (future Layer 3 extension).
