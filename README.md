# LSIG — Live System Intelligence Graph

A production-grade code intelligence platform that maps real execution traces back to AST nodes in real-time. Every CVE, pull request, and architectural decision is evaluated against what the system **actually does** in production — not what the documentation says it does.

The primary output is a **Change Impact Certificate** generated in under 60 seconds on every PR open event, answering:

1. What functions changed, and who owns them?
2. Which CVEs are newly exposed or removed by this change?
3. Which PII data flows are affected?
4. What is the blast radius (call graph depth ≤ 5) of the changed functions?

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Layer-by-Layer Reference](#layer-by-layer-reference)
  - [Layer 1 — Code Intelligence Engine](#layer-1--code-intelligence-engine)
  - [Layer 2 — Runtime Call Graph Engine](#layer-2--runtime-call-graph-engine)
  - [Layer 3 — Security Posture Engine](#layer-3--security-posture-engine)
  - [Layer 4 — Ownership and Data Flow Engine](#layer-4--ownership-and-data-flow-engine)
  - [Layer 5 — Graph Store and Query Layer](#layer-5--graph-store-and-query-layer)
  - [Layer 6 — Change Impact Certificate Engine](#layer-6--change-impact-certificate-engine)
  - [Layer 7 — Infrastructure and Deployment](#layer-7--infrastructure-and-deployment)
- [Quick Start (Local Development)](#quick-start-local-development)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Running Tests](#running-tests)
- [CI/CD Pipeline](#cicd-pipeline)
- [Extending LSIG](#extending-lsig)
- [Architecture Decision Records](#architecture-decision-records)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Developer Workflow                        │
│   git push → GitHub PR → Webhook → Certificate → Check Run      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Layer 6           │
                    │   Certificate       │
                    │   Engine            │
                    │   (FastAPI :8006)   │
                    └──────────┬──────────┘
                               │ queries
          ┌────────────────────▼──────────────────┐
          │              Layer 5                   │
          │   Graph Query API  (FastAPI :8005)     │
          │   NL→Cypher · Weaviate · VictoriaMetrics│
          └──┬─────────────┬──────────┬────────────┘
             │             │          │
    ┌────────▼──┐  ┌───────▼──┐  ┌───▼──────────┐
    │  Layer 1  │  │ Layer 3  │  │   Layer 4    │
    │  Code AST │  │ Security │  │  Ownership   │
    │  Neo4j    │  │ CVE/SBOM │  │  PII Flows   │
    └────────┬──┘  └──────────┘  └──────────────┘
             │
    ┌────────▼──────────────────────────┐
    │         Layer 2                   │
    │   eBPF Runtime Agent (Go)         │
    │   → Kafka → Flink → RUNTIME_CALLS │
    └───────────────────────────────────┘

Stores:
  Neo4j         — primary knowledge graph (all node/edge types)
  Weaviate      — vector embeddings for semantic search
  VictoriaMetrics — time-series call frequency history
  MinIO         — SBOM artifact archive
  Kafka         — runtime event stream (topic: runtime_calls)
```

### Data Model (Neo4j)

| Node | Key Properties |
|------|---------------|
| `Function` | id, name, file, line, language, service, owner_team |
| `Module` | id, name, path, service, owner_team |
| `APIEndpoint` | id, path, method, service, authenticated, exposes_pii |
| `DataField` | id, name, pii_likely, pii_type, service |
| `Dependency` | id, name, version, ecosystem, service, purl |
| `Vulnerability` | id, cve_id, severity, epss_score, in_kev |
| `Service` | id, name, regulatory_scope[], scope_confidence |
| `ExternalEndpoint` | id, url, path, service, severity |
| `Certificate` | id, pr_id, risk_level, payload (JSON) |

| Relationship | Meaning |
|---|---|
| `(Function)-[:CALLS]->(Function)` | Static call graph edge |
| `(Function)-[:RUNTIME_CALLS]->(Function)` | Observed at runtime (eBPF) |
| `(Function)-[:READS|WRITES]->(DataField)` | Field access |
| `(APIEndpoint)-[:HANDLED_BY]->(Function)` | Endpoint → handler |
| `(Dependency)-[:HAS_VULN]->(Vulnerability)` | CVE link (with reachability) |
| `(DataField)-[:FLOWS_TO]->(DataField)` | PII taint flow |
| `(ExternalEndpoint)-[:MAPS_TO]->(APIEndpoint)` | Nuclei discovery result |

---

## Layer-by-Layer Reference

### Layer 1 — Code Intelligence Engine

**Purpose:** Parse source code into the Neo4j graph using Tree-sitter (with regex fallback). Supports Python, JavaScript, TypeScript, Go, Java, and Ruby.

**Key Files:**

| File | Role |
|------|------|
| `layer1/code_ingester.py` | Main ingestion pipeline; incremental via git SHA state |
| `layer1/neo4j_client.py` | `run_query`, `upsert_node`, `upsert_relationship` — all idempotent MERGE |
| `layer1/retry_client.py` | Exponential backoff with full jitter for all external calls |
| `layer1/code_api.py` | FastAPI endpoints for graph queries and impact analysis |
| `schema/v1_init.cypher` | All Neo4j constraints, indexes, and schema version node |

**API Endpoints (port 8001):**

```
GET  /graph/functions?service=<name>       List all functions in a service
GET  /graph/calls?service=<name>           Static call graph edges
GET  /graph/entrypoints?service=<name>     APIEndpoint handler functions
POST /graph/impact                          {changed_file_ids} → blast radius
GET  /runtime/hotpaths?service=<name>      Functions with high call_count_24h
GET  /runtime/dead_code?service=<name>     Functions with no runtime evidence
GET  /runtime/blast_radius?service=<name>  Callers + affected endpoints
```

**How to ingest a repo:**

```python
from layer1.code_ingester import ingest

result = ingest(
    repo="https://github.com/myorg/myservice",
    service="myservice",
    work_dir="/tmp/repos/myservice",
    force_full=False,   # True to re-parse all files, False for incremental
)
print(f"Ingested {result.functions} functions, {result.endpoints} endpoints")
```

**Incremental state:** Stored in `/tmp/lsig_state/<service>.json` as the last-processed git SHA. Delete this file to force a full re-parse.

**Extending to a new language:**

1. Add file extensions to `LANG_EXTENSIONS` dict in `code_ingester.py`
2. Add a regex pattern entry to `_PATTERNS` dict for the language key
3. Optionally add a Tree-sitter grammar: `pip install tree-sitter-<lang>` and add lazy import in `_parse_with_tree_sitter()`

---

### Layer 2 — Runtime Call Graph Engine

**Purpose:** eBPF uprobes on every instrumented process emit call events to Kafka. A streaming job joins these events with the static graph and writes `RUNTIME_CALLS` edges.

**Key Files:**

| File | Role |
|------|------|
| `runtime_agent/main.go` | Go process: load eBPF, discover PIDs, perf buffer → Kafka |
| `runtime_agent/kafka_producer.go` | 60-second aggregation windows, keyed by service |
| `runtime_agent/ebpf/uprobe.bpf.c` | eBPF C program loaded into kernel |
| `runtime_agent/symbolizer.go` | IP → (function, file, line) via DWARF |
| `layer2/runtime_join.py` | Python: Kafka consumer + Neo4j writer (dev mode) |
| `layer2/kafka_schema.py` | Pydantic schema + JSON Schema for Kafka topic |
| `k8s/runtime-agent-daemonset.yaml` | Kubernetes DaemonSet with CAP_BPF, hostPID |

**Building the runtime agent:**

```bash
# Requires: clang, llvm, libbpf-dev, linux-headers
cd runtime_agent

# Compile eBPF C program
clang -O2 -g -target bpf -c ebpf/uprobe.bpf.c -o ebpf/uprobe.bpf.o

# Build Go binary
go build -o lsig-runtime-agent .
```

**Running in development (Python consumer, no Flink):**

```bash
export KAFKA_BROKERS=localhost:9092
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=password

python -m layer2.runtime_join standalone
```

**Running the Flink job (production):**

```python
from layer2.runtime_join import run_flink_job, FlinkJobConfig

run_flink_job(FlinkJobConfig(
    kafka_brokers="kafka:9092",
    neo4j_uri="bolt://neo4j:7687",
))
```

**RUNTIME_CALLS edge properties:**

| Property | Meaning |
|---|---|
| `call_count_24h` | Calls observed in last 24 hours |
| `call_count_7d` | Calls observed in last 7 days |
| `last_seen` | Unix timestamp of most recent call |

**Service name detection (Go agent):** The agent reads `/proc/<pid>/environ` for the `LSIG_SERVICE` env var (inject via Kubernetes Downward API). Falls back to the binary basename.

---

### Layer 3 — Security Posture Engine

**Purpose:** SBOM generation → CVE enrichment → three-step reachability algorithm → 70%+ reduction in CRITICAL false positives.

**Key Files:**

| File | Role |
|------|------|
| `layer3/sbom_ingester.py` | Runs Syft, parses CycloneDX, writes Dependency nodes |
| `layer3/cve_ingester.py` | OSV API + EPSS + CISA KEV enrichment |
| `layer3/reachability.py` | Three-step algorithm: static → runtime → attack surface |
| `layer3/nuclei_runner.py` | Nuclei external attack surface scanner |

**Three-step reachability algorithm:**

```
Step 1 — Static: Cypher path query depth ≤ 10 from vulnerable function to APIEndpoint
         Result: NOT_REACHABLE if no path found

Step 2 — Runtime: RUNTIME_CALLS.call_count_24h > 0 on any node in static path
         Upgrades reachability to HIGH or CRITICAL

Step 3 — Attack surface: ExternalEndpoint maps to endpoint in static path
         Upgrades reachability to CRITICAL (externally reachable)
```

**Running security ingestion for a service:**

```python
from layer3.sbom_ingester import ingest as ingest_sbom
from layer3.cve_ingester import ingest_for_service
from layer3.reachability import run_for_service

# Step 1: Generate and ingest SBOM
ingest_sbom("myorg/myservice:latest", service="myservice")

# Step 2: Enrich with CVE data
ingest_for_service("myservice")

# Step 3: Compute reachability
results = run_for_service("myservice")
print(f"{len(results)} CVEs analysed")
```

**Running the CVE daemon (background, every 6 hours):**

```python
from layer3.cve_ingester import run_daemon
run_daemon(interval_hours=6)
```

**Running Nuclei (attack surface discovery):**

```bash
# Requires: nuclei binary in PATH
export NUCLEI_BIN=/usr/local/bin/nuclei
```

```python
from layer3.nuclei_runner import scan
scan("myservice", "https://api.myservice.com")
```

**Reachability levels:**

| Level | Meaning |
|---|---|
| `CRITICAL` | Statically reachable + runtime evidence + externally exposed |
| `HIGH` | Statically reachable + runtime evidence |
| `MEDIUM` | Statically reachable, no runtime evidence |
| `LOW` | Adjacent dependency, no direct static path |
| `NOT_REACHABLE` | No path found in call graph |
| `UNKNOWN` | Not yet computed |

---

### Layer 4 — Ownership and Data Flow Engine

**Purpose:** Derive code ownership from CODEOWNERS + git blame (no manual YAML). Detect PII fields using regex fast path + Presidio NLP. Trace PII flows across service boundaries.

**Key Files:**

| File | Role |
|------|------|
| `layer4/ownership_ingester.py` | CODEOWNERS parser + git blame → owner_team/owner_email |
| `layer4/pii_detector.py` | 14-pattern regex fast path + Presidio NLP slow path |
| `layer4/taint_tracker.py` | CodeQL + graph-walk → FLOWS_TO edges |
| `layer4/regulatory_annotator.py` | Three-evidence scope derivation (annotation > PII > name) |

**Ownership derivation (CODEOWNERS takes precedence over git blame):**

```python
from layer4.ownership_ingester import ingest

ingest(
    repo_dir="/repos/myservice",
    service="myservice",
    since_sha="abc123",   # Optional: only process files changed since this SHA
)
```

**PII field detection:**

```python
from layer4.pii_detector import scan, detect_pii_in_name

# Quick check on a single field name
result = detect_pii_in_name("user_email_address")
# → PiiDetectionResult(pii_type="EMAIL", confidence=1.0, method="regex")

# Full repo scan (writes DataField nodes to Neo4j)
scan(repo_dir="/repos/myservice", service="myservice")
```

**Regulatory scope annotation:**

```python
from layer4.regulatory_annotator import annotate

evidence = annotate(service="myservice", repo_dir="/repos/myservice")
print(evidence.combined)       # ["PCI", "GDPR"]
print(evidence.confidence)     # "HIGH"
```

Evidence priority:
1. `lsig:regulatory=PCI,GDPR` comments in source code (highest)
2. PII field types present (`CREDIT_CARD` → PCI, `HEALTH_DATA` → HIPAA)
3. Service name pattern matching (`payment*` → PCI, `health*` → HIPAA)

**PII types detected:**

`EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `CREDENTIAL`, `DATE_OF_BIRTH`, `ADDRESS`, `PERSON_NAME`, `IP_ADDRESS`, `GOVERNMENT_ID`, `BANK_ACCOUNT`, `HEALTH_DATA`, `FINANCIAL`, `SENSITIVE_DEMOGRAPHIC`

---

### Layer 5 — Graph Store and Query Layer

**Purpose:** Unified query API over Neo4j (via Cypher), Weaviate (semantic search), and VictoriaMetrics (time-series metrics). Natural language to Cypher via Claude API with prompt caching.

**Key Files:**

| File | Role |
|------|------|
| `layer5/graph_api.py` | FastAPI app on port 8005 — all query/search/metrics endpoints |
| `layer5/nl_to_cypher.py` | Claude API NL→Cypher translation with schema prompt caching |
| `layer5/weaviate_index.py` | Weaviate sync and semantic search for Function/Endpoint/Vulnerability |
| `layer5/victoria_metrics.py` | Prometheus text-format write + MetricsQL query client |

**Starting the API:**

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=password
export ANTHROPIC_API_KEY=sk-ant-...
export WEAVIATE_URL=http://localhost:8080
export VICTORIAMETRICS_URL=http://localhost:8428
export LSIG_AUTH_DISABLED=true   # dev mode

uvicorn layer5.graph_api:app --port 8005 --reload
```

**Natural language queries:**

```bash
curl -X POST http://localhost:8005/query/nl \
  -H "Content-Type: application/json" \
  -d '{"question": "Which services have CRITICAL CVEs reachable from the internet?"}'
```

Response:

```json
{
  "question": "Which services have CRITICAL CVEs reachable from the internet?",
  "cypher": "MATCH (d:Dependency)-[r:HAS_VULN]->(v:Vulnerability) ...",
  "records": [...],
  "summary": "3 services have CRITICAL-reachability CVEs with external exposure...",
  "cached": true,
  "latency_ms": 420,
  "record_count": 3
}
```

**Semantic search:**

```bash
# Search by concept across all node types
curl "http://localhost:8005/search/all?q=authentication+middleware&limit=5"

# Scoped search
curl "http://localhost:8005/search/functions?q=payment+processing&service=payments"
```

**Syncing the Weaviate index:**

```bash
curl -X POST http://localhost:8005/search/index/sync \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"service": "auth"}'   # Omit service to sync all
```

**Prompt caching:** The 2,000-token LSIG schema context is sent with `cache_control: {"type": "ephemeral"}`. After the first call in a 5-minute window, subsequent calls are served from cache — reducing cost by ~75% and latency by ~30%. See [ADR-0005](docs/adr/0005-nl-to-cypher-prompt-caching.md).

---

### Layer 6 — Change Impact Certificate Engine

**Purpose:** Generate a cryptographically-signed Change Impact Certificate for every PR in < 60 seconds. Integrates with GitHub Checks API.

**Key Files:**

| File | Role |
|------|------|
| `layer6/certificate_engine.py` | Core: resolve functions → blast radius → security delta → narrative → sign |
| `layer6/github_webhook.py` | FastAPI webhook receiver (HMAC-validated) on port 8006 |
| `layer6/certificate_api.py` | REST API for generate/retrieve/verify certificates |
| `layer6/workflows/change_impact_workflow.py` | Temporal workflow for durable execution |

**Certificate structure:**

```json
{
  "certificate_id": "lsig-cert-github:myorg/auth:PR-42-1700000000",
  "pr_id": "github:myorg/auth:PR-42",
  "service": "auth",
  "generated_at": "2025-01-15T10:00:00+00:00",
  "generation_duration_ms": 18420,
  "risk_level": "CRITICAL",
  "narrative": "PR #42 modifies JWT validation. CVE-2023-9999 (CISA KEV-confirmed, EPSS 91%) is now reachable from the public login endpoint. Immediate security review required before merge.",
  "changed_functions": [...],
  "blast_radius": {
    "direct_callers": [...],
    "transitive_callers": [...],
    "affected_endpoints": [...],
    "affected_services": ["api", "payments"]
  },
  "security_delta": {
    "new_critical_vulns": [...],
    "pii_flows_added": [...],
    "net_risk_change": "INCREASED"
  },
  "signature": "a3f8b2c1..."
}
```

**Risk levels:**

| Level | Trigger |
|---|---|
| `CRITICAL` | CRITICAL-reachability CVE that is CISA KEV-confirmed |
| `HIGH` | CRITICAL-reachability CVE, or PII flow to external endpoint |
| `MEDIUM` | Any CVE in scope, or unregulated PII flow |
| `LOW` | Blast radius crosses service boundaries |
| `NONE` | No issues detected |

**Setting up the GitHub webhook:**

1. In your GitHub repo settings: **Settings → Webhooks → Add webhook**
2. Payload URL: `https://lsig.example.com/webhook/github`
3. Content type: `application/json`
4. Events: `Pull requests`
5. Secret: set `LSIG_GITHUB_WEBHOOK_SECRET` to the same value

**Generating a certificate manually:**

```bash
curl -X POST http://localhost:8006/certificate/generate \
  -H "Content-Type: application/json" \
  -d '{
    "pr_id": "github:myorg/auth:PR-42",
    "service": "auth",
    "changed_files": ["auth/jwt.py", "auth/models.py"]
  }'
```

**Verifying a certificate:**

```bash
curl -X POST http://localhost:8006/certificate/verify \
  -H "Content-Type: application/json" \
  -d '{"certificate": {...}}'
# → {"valid": true, "certificate_id": "lsig-cert-..."}
```

**Using Temporal (production):**

```bash
# Start worker
python -m layer6.workflows.change_impact_workflow worker

# Trigger from CLI (testing)
python -m layer6.workflows.change_impact_workflow trigger \
  --pr github:myorg/auth:PR-42 \
  --service auth \
  --files auth/jwt.py,auth/models.py
```

---

### Layer 7 — Infrastructure and Deployment

**Purpose:** Helm chart, Kind local cluster, Prometheus alerting, GitHub Actions CI.

**Key Files:**

| File | Role |
|------|------|
| `helm/lsig/` | Full Helm chart — deployments, services, schema init Job |
| `k8s/kind-cluster.yaml` | Local Kind cluster with eBPF mounts |
| `k8s/runtime-agent-daemonset.yaml` | DaemonSet with CAP_BPF, hostPID:true |
| `k8s/prometheus-servicemonitor.yaml` | ServiceMonitors + alerting rules |
| `.github/workflows/ci.yml` | CI: Python tests, Go build, Helm lint, Dashboard build |

---

## Quick Start (Local Development)

### Prerequisites

| Tool | Min Version | Install |
|---|---|---|
| Python | 3.11 | `pyenv install 3.11` |
| Go | 1.22 | `go.dev/dl` |
| Node.js | 20 | `nvm install 20` |
| Docker + Compose | Latest | `docker.com` |
| Neo4j | 5.x | via Docker below |
| clang + llvm | 14+ | `apt install clang llvm libbpf-dev` |

### 1. Start backing services

```bash
# Start Neo4j, Kafka, VictoriaMetrics, Weaviate, MinIO
cat > docker-compose.yml << 'EOF'
version: "3.9"
services:
  neo4j:
    image: neo4j:5.18-community
    environment:
      NEO4J_AUTH: neo4j/lsigpassword
      NEO4J_PLUGINS: '["apoc"]'
    ports: ["7474:7474", "7687:7687"]
    volumes: ["neo4j_data:/data"]

  kafka:
    image: bitnami/kafka:3.7
    environment:
      KAFKA_CFG_NODE_ID: 0
      KAFKA_CFG_PROCESS_ROLES: controller,broker
      KAFKA_CFG_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
      KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_CFG_CONTROLLER_QUORUM_VOTERS: 0@kafka:9093
      KAFKA_CFG_CONTROLLER_LISTENER_NAMES: CONTROLLER
    ports: ["9092:9092"]

  victoriametrics:
    image: victoriametrics/victoria-metrics:latest
    ports: ["8428:8428"]

  weaviate:
    image: semitechnologies/weaviate:1.25.0
    environment:
      QUERY_DEFAULTS_LIMIT: 25
      AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED: "true"
      PERSISTENCE_DATA_PATH: /var/lib/weaviate
      DEFAULT_VECTORIZER_MODULE: text2vec-transformers
      ENABLE_MODULES: text2vec-transformers
      TRANSFORMERS_INFERENCE_API: http://t2v-transformers:8080
    ports: ["8080:8080", "50051:50051"]
    depends_on: [t2v-transformers]

  t2v-transformers:
    image: semitechnologies/transformers-inference:sentence-transformers-all-MiniLM-L6-v2
    environment:
      ENABLE_CUDA: 0

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports: ["9000:9000", "9001:9001"]
    volumes: ["minio_data:/data"]

volumes:
  neo4j_data:
  minio_data:
EOF

docker compose up -d
```

### 2. Install Python dependencies

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Install spaCy model for Presidio NLP
python -m spacy download en_core_web_lg
```

### 3. Apply Neo4j schema

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=lsigpassword

# Wait for Neo4j to be ready, then apply schema
python - << 'EOF'
from layer1.neo4j_client import run_query
import time

for i in range(30):
    try:
        run_query("RETURN 1")
        break
    except Exception:
        time.sleep(2)

with open("schema/v1_init.cypher") as f:
    schema = f.read()

for stmt in schema.split(";"):
    stmt = stmt.strip()
    if stmt and not stmt.startswith("//"):
        try:
            run_query(stmt)
        except Exception as e:
            print(f"WARN (may already exist): {e}")

print("Schema applied.")
EOF
```

### 4. Set environment variables

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=lsigpassword
export ANTHROPIC_API_KEY=sk-ant-...        # Required for NL→Cypher and certificates
export KAFKA_BROKERS=localhost:9092
export VICTORIAMETRICS_URL=http://localhost:8428
export WEAVIATE_URL=http://localhost:8080
export LSIG_AUTH_DISABLED=true             # Disable auth for local dev
export LSIG_CERT_SECRET=dev-secret
```

### 5. Ingest a sample repository

```bash
python - << 'EOF'
from layer1.code_ingester import ingest

result = ingest(
    repo="https://github.com/expressjs/express",
    service="express",
    work_dir="/tmp/lsig-demo/express",
)
print(result)
EOF
```

### 6. Start the APIs

```bash
# Terminal 1 — Graph Query API
uvicorn layer5.graph_api:app --port 8005 --reload

# Terminal 2 — Certificate API + Webhook
uvicorn layer6.certificate_api:app --port 8006 --reload
```

### 7. Start the dashboard

```bash
cd dashboard
npm install
npm run dev
# Open http://localhost:3000
```

### 8. Generate your first certificate

```bash
curl -X POST http://localhost:8006/certificate/generate \
  -H "Content-Type: application/json" \
  -d '{
    "pr_id": "demo:PR-1",
    "service": "express",
    "changed_files": ["lib/router/index.js"]
  }'
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `NEO4J_URI` | Yes | `bolt://localhost:7687` | Neo4j Bolt connection URI |
| `NEO4J_USER` | Yes | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | Yes | — | Neo4j password |
| `ANTHROPIC_API_KEY` | Yes | — | Claude API key (NL→Cypher + narrative) |
| `KAFKA_BROKERS` | Layer 2 | `localhost:9092` | Comma-separated Kafka broker addresses |
| `KAFKA_TOPIC` | Layer 2 | `runtime_calls` | Kafka topic for runtime events |
| `VICTORIAMETRICS_URL` | Layer 5 | `http://localhost:8428` | VictoriaMetrics base URL |
| `WEAVIATE_URL` | Layer 5 | `http://localhost:8080` | Weaviate HTTP base URL |
| `WEAVIATE_GRPC_HOST` | Layer 5 | `localhost` | Weaviate gRPC host |
| `WEAVIATE_GRPC_PORT` | Layer 5 | `50051` | Weaviate gRPC port |
| `LSIG_AUTH_DISABLED` | No | `false` | Set `true` to disable JWT auth (dev only) |
| `LSIG_CERT_SECRET` | Layer 6 | `dev-secret-change-in-prod` | HMAC signing key for certificates |
| `LSIG_GITHUB_WEBHOOK_SECRET` | Layer 6 | — | GitHub webhook HMAC secret |
| `LSIG_GITHUB_TOKEN` | Layer 6 | — | GitHub PAT with `repo` + `checks:write` scopes |
| `LSIG_SERVICE_MAP` | Layer 6 | — | `repo:service` pairs e.g. `myorg/auth:auth,myorg/pay:payments` |
| `LSIG_SERVICE` | Agent | — | Inject into containers to identify service name |
| `MINIO_ENDPOINT` | Layer 3 | `localhost:9000` | MinIO/S3 endpoint for SBOM archive |
| `MINIO_ACCESS_KEY` | Layer 3 | `minioadmin` | MinIO access key |
| `MINIO_SECRET_KEY` | Layer 3 | `minioadmin` | MinIO secret key |
| `NUCLEI_BIN` | Layer 3 | `nuclei` | Path to Nuclei binary |
| `SYFT_BIN` | Layer 3 | `syft` | Path to Syft binary |
| `CODEQL_BIN` | Layer 4 | `codeql` | Path to CodeQL binary (optional) |

---

## API Reference

### Graph Query API (port 8005)

#### `POST /query/nl`
Natural language query translated to Cypher via Claude.

```json
// Request
{"question": "Which services expose PII to unauthenticated endpoints?"}

// Response
{
  "question": "...",
  "cypher": "MATCH ...",
  "records": [...],
  "summary": "2 services expose PII without authentication...",
  "cached": true,
  "latency_ms": 380,
  "record_count": 2
}
```

#### `GET /query/service_summary?service=<name>`
Aggregated health snapshot across all four layers.

#### `GET /query/change_impact?service=<name>&function_ids=id1,id2`
Pre-merge impact analysis for a set of function IDs.

#### `GET /search/functions?q=<text>&service=<name>&limit=10`
Semantic search over Function nodes using Weaviate.

#### `GET /search/endpoints?q=<text>&service=<name>&limit=10`
Semantic search over APIEndpoint nodes.

#### `GET /search/vulnerabilities?q=<text>&limit=10`
Semantic search over Vulnerability nodes.

#### `GET /search/all?q=<text>&limit=5`
Cross-type semantic search, results sorted by certainty.

#### `GET /metrics/call_history?service=<name>&function=<name>&days=7`
Call count time series from VictoriaMetrics.

#### `GET /metrics/system`
LSIG system health: VictoriaMetrics reachable, certificate p95, FP reduction rate.

#### `POST /query/cypher` (admin only)
Execute raw Cypher. Only read operations (blocked by validator).

#### `POST /search/index/sync` (admin only)
Trigger Weaviate re-sync from Neo4j.

### Certificate API (port 8006)

#### `POST /certificate/generate`
Generate a signed Change Impact Certificate synchronously.

```json
// Request
{
  "pr_id": "github:myorg/auth:PR-42",
  "service": "auth",
  "changed_files": ["auth/jwt.py"],
  "repo_dir": ""
}
```

#### `GET /certificate/{cert_id}`
Retrieve a stored certificate by ID.

#### `POST /certificate/verify`
Verify HMAC-SHA256 signature of a certificate payload.

#### `GET /pr/{pr_id}/certificate`
Latest certificate for a PR identifier.

#### `POST /webhook/github`
GitHub `pull_request` webhook receiver. Requires `X-Hub-Signature-256` header.

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# By layer
pytest tests/test_code_ingester.py        # Layer 1
pytest tests/test_runtime_join.py         # Layer 2
pytest tests/test_security.py             # Layer 3
pytest tests/test_ownership_pii.py        # Layer 4
pytest tests/test_graph_query.py          # Layer 5
pytest tests/test_certificate_engine.py   # Layer 6

# With coverage
pytest tests/ --cov=layer1 --cov=layer2 --cov=layer3 \
              --cov=layer4 --cov=layer5 --cov=layer6 \
              --cov-report=html

# Against real Neo4j (integration tests)
NEO4J_URI=bolt://localhost:7687 \
NEO4J_USER=neo4j \
NEO4J_PASSWORD=lsigpassword \
pytest tests/ -m neo4j -v
```

**Test markers:**

| Marker | Meaning |
|---|---|
| `neo4j` | Requires running Neo4j |
| `slow` | Takes >10s (excluded from fast CI) |
| `integration` | Requires external services |

---

## CI/CD Pipeline

GitHub Actions at `.github/workflows/ci.yml` runs on every push and PR:

| Job | What it checks |
|---|---|
| `python-layer1` | mypy type check, ruff lint, unit + Neo4j integration tests |
| `python-layer56` | Layer 5 graph query + Layer 6 certificate engine tests |
| `go-runtime-agent` | `go vet`, staticcheck for the eBPF agent |
| `helm-lint` | `helm lint` + `helm template` validation |
| `dashboard-build` | TypeScript compile + Vite build |

---

## Extending LSIG

### Adding a new language to the code parser

1. Add file extensions in `layer1/code_ingester.py`:
   ```python
   LANG_EXTENSIONS = {
       ...
       ".rs": "rust",
   }
   ```
2. Add regex patterns to `_PATTERNS`:
   ```python
   _PATTERNS = {
       ...
       "rust": {
           "function": re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)", re.MULTILINE),
           "api_endpoint": re.compile(r'#\[(?:get|post|put|delete)\("([^"]+)"\)]', re.MULTILINE),
       }
   }
   ```
3. Optionally add Tree-sitter grammar: `pip install tree-sitter-rust` and add the lazy import.

### Adding a new PII type

1. Add a regex to `_NAME_PATTERNS` in `layer4/pii_detector.py`:
   ```python
   _NAME_PATTERNS = {
       ...
       "PASSPORT_NUMBER": re.compile(r"\bpassport[\W_]*(num|number|no)\b", re.I),
   }
   ```
2. Add Presidio entity mapping if the Presidio recognizer supports it.
3. Add a `_PII_TO_SCOPE` mapping in `layer4/regulatory_annotator.py` if the type implies a regulatory scope.

### Adding a new NL query pattern

The NL→Cypher system uses the `LSIG_SCHEMA_CONTEXT` string in `layer5/nl_to_cypher.py` as the Claude prompt. Add example queries to the "Common query patterns" section to guide generation for new patterns.

### Adding a new metric to VictoriaMetrics

1. Write in `layer5/victoria_metrics.py`:
   ```python
   def write_my_metric(self, value: float, labels: dict) -> bool:
       line = _build_prometheus_line("lsig_my_metric", labels, value)
       return self.write([line])
   ```
2. Add a query method:
   ```python
   def query_my_metric(self) -> float | None:
       results = self.query("sum(lsig_my_metric)")
       ...
   ```
3. Expose it in the `/metrics/system` endpoint in `layer5/graph_api.py`.

### Deploying to Kubernetes

```bash
# Create the secret first
kubectl create namespace lsig
kubectl create secret generic lsig-secrets -n lsig \
  --from-literal=neo4j-password=<password> \
  --from-literal=anthropic-api-key=<key> \
  --from-literal=github-token=<token> \
  --from-literal=github-webhook-secret=<secret> \
  --from-literal=cert-secret=<hmac-secret>

# Install with Helm
helm dependency update helm/lsig/
helm install lsig helm/lsig/ -n lsig \
  --set image.tag=1.0.0 \
  --set ingress.hosts[0].host=lsig.example.com

# Deploy runtime agent DaemonSet
kubectl apply -f k8s/runtime-agent-daemonset.yaml

# Apply Prometheus monitoring
kubectl apply -f k8s/prometheus-servicemonitor.yaml
```

**Local Kind cluster:**

```bash
kind create cluster --config k8s/kind-cluster.yaml --name lsig
kubectl cluster-info --context kind-lsig
```

---

## Architecture Decision Records

| ADR | Decision |
|---|---|
| [ADR-0001](docs/adr/0001-regex-fallback-for-tree-sitter.md) | Two-tier parsing: Tree-sitter primary, regex fallback |
| [ADR-0002](docs/adr/0002-ebpf-uprobe-runtime-tracing.md) | eBPF uprobes over OpenTelemetry for zero-code-change instrumentation |
| [ADR-0003](docs/adr/0003-three-step-reachability-engine.md) | Three-step reachability: static → runtime → attack surface |
| [ADR-0004](docs/adr/0004-pii-detection-two-tier.md) | Regex fast path + Presidio NLP for PII detection |
| [ADR-0005](docs/adr/0005-nl-to-cypher-prompt-caching.md) | Anthropic prompt caching on 2,000-token schema block |

---

## Troubleshooting

### Neo4j connection refused
```
neo4j.exceptions.ServiceUnavailable: Failed to establish connection
```
- Check Neo4j is running: `docker ps | grep neo4j`
- Verify `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` are set correctly
- Neo4j takes 20–30s to start; the schema init script retries automatically

### eBPF agent: permission denied
```
failed to load eBPF program: operation not permitted
```
- The agent requires `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`
- On Linux: `sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+eip ./lsig-runtime-agent`
- In Kubernetes: use the provided DaemonSet which sets these capabilities

### Weaviate: vector module not available
```
RuntimeError: weaviate-client not installed
```
```bash
pip install weaviate-client>=4.0
```
If the `text2vec-transformers` module is not enabled, LSIG falls back to keyword-only search and logs a warning.

### Claude API: quota exceeded
```
anthropic.RateLimitError: Rate limit exceeded
```
- The `with_retry` wrapper retries with exponential backoff (up to 3 attempts)
- If quota is exceeded for the session, the NL query falls back to returning an error in `NLQueryResult.error`
- Consider upgrading to a higher Claude API tier or caching more aggressively

### Certificate generation slow (> 60s)
- Check Neo4j query performance: `EXPLAIN MATCH ...` to verify indexes are used
- The blast radius query uses APOC `apoc.path.subgraphNodes` — ensure APOC is installed
- Without APOC, falls back to single-hop query (shallower blast radius but faster)
- VictoriaMetrics write failures are non-blocking; check `lsig_runtime_agent_kafka_events_total` metric

### Kafka: No messages consumed
```
KafkaTimeoutError: Request timed out
```
- Verify `KAFKA_BROKERS` points to the correct host:port
- Check topic exists: `kafka-topics.sh --bootstrap-server localhost:9092 --list`
- Create topic if missing: `kafka-topics.sh --bootstrap-server localhost:9092 --create --topic runtime_calls --partitions 12`

### Helm: missing dependency charts
```
Error: found in Chart.yaml, but missing in charts/ directory: neo4j
```
```bash
helm dependency update helm/lsig/
```

---

## Implementation Rules (for contributors)

These rules were applied throughout the build and must be maintained:

1. **No manual YAML for ownership or regulatory scope** — always derive from CODEOWNERS, git blame, source annotations, or PII field types
2. **Runtime evidence beats static analysis** — RUNTIME_CALLS data always overrides static call graph conclusions
3. **Append-first graph writes** — use `MERGE + SET` never `DELETE`; use `deprecated_at` timestamps instead of deletion
4. **All external calls are idempotent and retryable** — use `with_retry()` from `layer1/retry_client.py`
5. **No secrets in code** — all credentials via environment variables; Kubernetes secrets for production
6. **Self-describing errors** — API errors include `error_type`, `detail`, and `suggestion` fields
7. **Incremental ingestion** — never re-parse everything; use git SHA state files and Neo4j MERGE semantics
8. **Test with real repos** — acceptance tests ingest real public repos (Express.js, Gin), not synthetic fixtures
