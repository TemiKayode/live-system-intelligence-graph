# LSIG — Linux System Intelligence Graph

[![Build](https://github.com/TemiKayode/lsig/actions/workflows/ci.yml/badge.svg)](https://github.com/TemiKayode/lsig/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![eBPF](https://img.shields.io/badge/eBPF-kernel--level-orange)](https://ebpf.io/)
[![Linux](https://img.shields.io/badge/linux-5.8%2B-yellow)](https://kernel.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**LSIG uses eBPF to attach to the Linux kernel and capture TCP/IP socket events in real time — building a live graph of network connections between every process on the machine.**

No agents to install in target processes. No userspace polling. The kernel tells you exactly what's happening, the moment it happens, with zero overhead on the observed application.

---

## Why eBPF?

Traditional network monitoring tools work in userspace:

```
netstat / ss     → reads /proc/net/tcp — a snapshot, not a stream
tcpdump          → captures packets — raw bytes, no process context  
strace           → per-process syscall tracing — high overhead
```

eBPF is different. You write a small program that the kernel JIT-compiles and runs in a sandboxed VM at kernel hook points — in this case, `tcp_connect`, `tcp_close`, and `tcp_accept`. The kernel calls your program **on every socket event**, passing process ID, source/destination IP, port, and timestamp directly from kernel data structures.

The result: **zero-overhead, process-aware, real-time network topology** — the same technology used by Datadog's NPM product, Cilium's network policies, and CrowdStrike's Falcon sensor.

---

## What LSIG captures

```
LSIG Network Graph — Live View
────────────────────────────────────────────────────────────────
TIME         PID    PROCESS        SRC              DST          DIRECTION
────────────────────────────────────────────────────────────────
14:23:01.012  4821  nginx          10.0.0.5:80      10.0.0.12:54321  ACCEPT
14:23:01.015  4822  postgres       127.0.0.1:5432   127.0.0.1:54410  ACCEPT
14:23:01.018  2341  python3        127.0.0.1:54410  127.0.0.1:5432   CONNECT
14:23:01.102  2341  python3        10.0.0.5:54312   93.184.216.34:443 CONNECT
14:23:04.881  4821  nginx          10.0.0.5:80      10.0.0.12:54321  CLOSE (3.8s)
────────────────────────────────────────────────────────────────

Process Dependency Graph:
  nginx (4821) ──► python3 (2341) ──► postgres (4822)
                └──────────────────► external:443 (api.example.com)
```

LSIG builds this graph continuously and can export it as JSON, Graphviz DOT, or a live terminal view.

---

## How it works

```
Linux Kernel
┌──────────────────────────────────────────┐
│                                          │
│  tcp_connect hook ──► eBPF program       │
│  tcp_accept hook  ──► (kernel-sandboxed) │
│  tcp_close hook   ──►       │            │
│                             │            │
│                         perf ring        │
│                          buffer          │
└─────────────────────────────┼────────────┘
                              │
                    Python userspace
                    ┌─────────▼────────┐
                    │  Event consumer  │
                    │  (BCC / libbpf)  │
                    │                  │
                    │  PID → process   │
                    │  IP → hostname   │
                    │  build graph     │
                    └─────────┬────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         Terminal          JSON export    Graphviz DOT
         live view        (for SIEM)      (visualise)
```

The eBPF program runs inside the kernel and passes events through a `perf_event_array` ring buffer to the Python consumer process. The consumer enriches each event with process name (from `/proc/<pid>/comm`), resolves IPs to hostnames where possible, and maintains the in-memory connection graph.

---

## Requirements

- **Linux kernel 5.8+** (for BPF ring buffer support)
- **Python 3.10+**
- **BCC (BPF Compiler Collection)** or **libbpf** + `bpftool`
- **Root / CAP_BPF capability** (eBPF programs require elevated privileges)

**Ubuntu / Debian:**
```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

**Fedora / RHEL:**
```bash
sudo dnf install bcc bcc-tools python3-bcc kernel-devel
```

---

## Quick Start

```bash
git clone https://github.com/TemiKayode/lsig.git
cd lsig
pip install -r requirements.txt

# Run LSIG (requires root for eBPF)
sudo python lsig.py

# With options
sudo python lsig.py --mode graph      # show process dependency graph
sudo python lsig.py --mode stream     # live event stream (default)
sudo python lsig.py --export json     # write events to lsig_events.json
sudo python lsig.py --export dot      # write graph to lsig_graph.dot
sudo python lsig.py --filter pid=1234 # monitor a specific process
sudo python lsig.py --filter comm=nginx # monitor by process name
```

**Visualise the graph:**
```bash
sudo python lsig.py --export dot
dot -Tpng lsig_graph.dot -o network_graph.png
```

---

## Use Cases

**Security monitoring**
- Detect unexpected outbound connections from a process (e.g., a web server making external calls it shouldn't)
- Map the actual network attack surface of a running application
- Identify lateral movement: a compromised process connecting to internal services

**Microservice dependency mapping**
- Automatically discover service-to-service connections without reading config files
- Validate that actual runtime connections match documented architecture

**Performance analysis**
- Identify processes making excessive short-lived connections (connection pool misconfiguration)
- Find processes talking to services they shouldn't (misconfigured service discovery)

---

## Project Structure

```
lsig/
├── bpf/
│   └── tcp_monitor.c     # eBPF C program — attaches to tcp_connect/accept/close
├── lsig/
│   ├── consumer.py       # Python perf buffer consumer
│   ├── graph.py          # In-memory connection graph
│   ├── enricher.py       # PID → process name, IP → hostname
│   ├── exporters/
│   │   ├── json.py       # JSON event export
│   │   ├── dot.py        # Graphviz DOT export
│   │   └── terminal.py   # Live terminal view
│   └── filters.py        # PID / comm / IP filtering
├── lsig.py               # CLI entry point
├── requirements.txt
└── README.md
```

---

## Example JSON Output

```json
{
  "timestamp": "2024-01-15T14:23:01.018Z",
  "event": "CONNECT",
  "pid": 2341,
  "process": "python3",
  "src_ip": "127.0.0.1",
  "src_port": 54410,
  "dst_ip": "127.0.0.1",
  "dst_port": 5432,
  "dst_process": "postgres",
  "dst_pid": 4822,
  "duration_ms": null
}
```

---

## Kernel Hook Points

| Hook | Event | Data captured |
|------|-------|---------------|
| `kprobe/tcp_connect` | Outbound connection initiated | PID, src IP:port, dst IP:port |
| `kprobe/inet_csk_accept` | Inbound connection accepted | PID, src IP:port, dst IP:port |
| `kprobe/tcp_close` | Connection closed | PID, IPs, duration |

All hooks use kprobes — they attach to existing kernel functions without modifying the kernel or requiring kernel module compilation.

---

## Related Projects

- **InfraLens** — distributed observability platform with custom storage engine (uses OpenTelemetry, not eBPF, but solves the same "understand your system" problem at a higher level)
- **FaceSentinel** — LSIG's network monitoring can feed into FaceSentinel's anomaly detection for unusual identity verification traffic patterns

---

## License

MIT
