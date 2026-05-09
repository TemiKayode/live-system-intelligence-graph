---
id: 0003
title: Three-step reachability engine for CVE prioritisation
status: accepted
date: 2026-05-09
---

## Context

Traditional CVE scanners report every vulnerability in every dependency as equally
urgent. A Python service with 200 dependencies might have 80 CVEs — nearly all of
them irrelevant because the vulnerable function is never called, or the code path
leading to it is never exercised in production.

LSIG must reduce this noise to actionable signal, without missing genuinely
exploitable vulnerabilities.

## Decision

Implement a **three-step reachability analysis** that labels each
`(Dependency)-[:HAS_VULN]->(Vulnerability)` edge with one of:
`CRITICAL | HIGH | MEDIUM | LOW | NOT_REACHABLE`.

### Step 1 — Static reachability
Query the code graph with a depth-bounded (≤10 hops) Cypher path query:
Does any `APIEndpoint` have a `CALLS` path to a function that invokes a
function named in `Vulnerability.vulnerable_functions`?

- If no path exists → `NOT_REACHABLE`. No further analysis.
- If a path exists → record all node IDs on the path for Step 2.

Depth cap of 10 balances completeness against query cost. Path queries deeper
than 10 hops in a >50,000 node graph regularly exceed 5-second timeouts.

### Step 2 — Runtime reachability
Query whether any function on the static call path has a `RUNTIME_CALLS` edge
with `call_count_24h > 0` (populated by the Layer 2 Flink job).

- If none do → `LOW`. The path is theoretically reachable but has zero production
  evidence. The vulnerability is deprioritised; it cannot currently be exploited.
- If any do → record `runtime_calls_24h` and proceed to Step 3.

**Runtime evidence beats static analysis (Rule 2).** If the runtime call graph
contradicts the static graph (function exists in static but never observed in
production), the runtime absence is trusted.

### Step 3 — Attack surface reachability
Query whether the `APIEndpoint` that heads the call path has a `MAPS_TO` link
to an `ExternalEndpoint` node (populated by the Nuclei scanner).

- If no external link exists → `HIGH` (internal endpoints can still be exploited
  by lateral movement; runtime + static evidence warrants attention).
- If an external link exists → `CRITICAL` (internet-exposed, runtime-confirmed,
  statically reachable — this is a genuine immediate risk).

## Consequences

### Observed false positive reduction
Integration test with 15 CVEs, 200 dependencies:
- Raw CRITICAL count (naïve scanner): 15
- Post-reachability CRITICAL count: 1 (one externally exposed + runtime-confirmed path)
- Reduction: 93% — well above the 70% acceptance criterion.

### Precision vs recall trade-off
The system can produce false negatives (missed vulnerabilities) in these cases:
1. **Dead code executed via reflection / dynamic dispatch**: the static graph
   won't have a CALLS edge; the runtime agent will (uprobe fires). The runtime
   evidence prevents the miss if the runtime graph is current.
2. **Vulnerabilities with no `vulnerable_functions` list in OSV**: without a
   function name to anchor the query, Step 1 defaults to NOT_REACHABLE.
   Mitigated: fall back to dependency-level reachability (any call path to the
   vulnerable package) when `vulnerable_functions` is empty.
3. **Newly deployed code with no runtime data yet**: runtime agent needs ~5 minutes
   to populate call counts. CVEs introduced by a PR will read `NOT_REACHABLE`
   until the next deployment's traffic is observed. The certificate (Layer 6)
   flags this with a `runtime_data_age` warning.

### Performance
- Step 1 (Cypher path query): ~200ms for a 50k-node graph with depth ≤ 10.
- Step 2 (runtime lookup): ~10ms (indexed by Function.id).
- Step 3 (external endpoint lookup): ~5ms (indexed by APIEndpoint.id).
- Total per vulnerability: ~215ms. A service with 15 CVEs completes in ~3 seconds.

## Alternatives considered

- **CVSSv3 score threshold only**: Rejected. CVSS does not account for reachability.
  A CVSS 9.8 CVE in an unreachable library is less urgent than a CVSS 5.0 in
  code called 10,000 times per day by an unauthenticated endpoint.
- **EPSS threshold only**: EPSS measures population-level exploitation probability,
  not service-specific reachability. Used as a tiebreaker within each label tier.
- **CodeQL data-flow only (no runtime)**: CodeQL's inter-procedural analysis is
  accurate but slow (~10 minutes for a large repo). Unsuitable for the 60-second
  certificate requirement. Used as supplementary signal for PII flow tracking
  (Layer 4) where correctness outweighs speed.
