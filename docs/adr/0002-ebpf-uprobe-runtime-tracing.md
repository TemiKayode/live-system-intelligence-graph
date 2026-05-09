---
id: 0002
title: eBPF uprobes for runtime function tracing (vs. OpenTelemetry instrumentation)
status: accepted
date: 2026-05-09
---

## Context

Layer 2 must map production execution to AST nodes without requiring changes to
application source code. Two approaches were evaluated:

**Option A — OpenTelemetry auto-instrumentation**
Inject an OTel agent into each service at startup (Java agent, Python sitecustomize,
Go compile-time). Collect spans and extract function names from span/frame names.

**Option B — eBPF uprobes**
Attach kernel-level uprobes to every running process from a single DaemonSet.
No changes to application code or container images.

## Decision

Use **eBPF uprobes** (Option B) as the primary runtime call source.

OTel is retained as a supplementary source: if a service already emits OTel traces,
the runtime join job will additionally ingest those spans. But the system must work
without OTel.

## Rationale

| Criterion | OTel auto-instrumentation | eBPF uprobes |
|---|---|---|
| Code change required | Yes (for Go, Rust) | No |
| Container image change | Yes (agent injection) | No |
| Coverage | Sampled (typically 1–10%) | Full population |
| Overhead | 1–5% per traced service | ~0.5% CPU per node |
| Language support | Per-language agents | Any ELF binary |
| Symbol resolution latency | Zero (SDK provides names) | ~1µs (llvm-symbolizer cache) |
| Accuracy on hot paths | Sampling bias | Exact counts |

The core LSIG value prop is "what code actually executes" — sampling-biased OTel
cannot satisfy this for infrequently-called but security-critical paths.

## Consequences

- **Privilege requirements**: The DaemonSet needs `CAP_SYS_PTRACE`, `CAP_BPF`,
  and `CAP_PERFMON`. This is accepted; the agent runs read-only and is audited.
- **Kernel version floor**: Linux 5.8+ required for `CAP_BPF` (replacing `CAP_SYS_ADMIN`
  for BPF). Nodes on older kernels fall back to OTel span ingestion.
- **Symbol stripping**: Production binaries compiled without debug info will not
  symbolize correctly. The Helm chart documents a build flag requirement
  (`-gcflags="-N -l"` for Go, `--no-strip` for compiled languages). Interpreted
  languages (Python, Ruby) symbolize via `/proc/<pid>/maps` without debug info.
- **60-second aggregation window**: Raw uprobe events are aggregated before Kafka
  emission to limit throughput (Rule 7: incremental, not raw-flood). The window
  is configurable via `LSIG_FLUSH_INTERVAL_S`.

## Alternatives considered

- **Cilium Hubble**: Provides network-level call graphs between services but cannot
  resolve intra-service function calls. Rejected as insufficient granularity.
- **Parca/Pyroscope continuous profiling**: CPU-sample based — misses functions that
  complete quickly (< 1ms). Retained as a supplementary latency signal but not
  sufficient for call-count accuracy.
- **Java JVMTI agent**: Provides function-level tracing for JVM languages with no
  symbol stripping concern. Accepted as a future enhancement for Java services.
