"""
Layer 5 — Weaviate Embedding Index.

Indexes Function, APIEndpoint, and Vulnerability node descriptions in Weaviate
to power fuzzy / semantic search queries against the LSIG graph.

Use cases:
  - "find all auth-related functions" → vector similarity → exact Neo4j node IDs
  - "which endpoints handle payments?" → semantic match → APIEndpoint nodes
  - "CVEs related to SQL injection" → similarity → Vulnerability nodes

Architecture:
  - Three Weaviate classes: LsigFunction, LsigEndpoint, LsigVulnerability
  - Each object stores the Neo4j node ID + a text description for embedding
  - The text description is assembled from node properties (name, file, service, etc.)
  - Weaviate uses its built-in text2vec-transformers (all-MiniLM-L6-v2) module
  - Synchronisation: full re-index on schema change, incremental on node updates

Usage:
    from layer5.weaviate_index import WeaviateIndex
    idx = WeaviateIndex()
    idx.sync_from_neo4j()
    results = idx.search_functions("authentication middleware", limit=10)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from layer1.neo4j_client import run_query
from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)

# ─── Weaviate client ──────────────────────────────────────────────────────────

def _weaviate_client():
    try:
        import weaviate
        url = os.environ.get("WEAVIATE_URL", "http://localhost:8080")
        # weaviate-client v4 API
        client = weaviate.connect_to_custom(
            http_host=url.replace("http://", "").replace("https://", "").split(":")[0],
            http_port=int(url.rsplit(":", 1)[-1]) if ":" in url.rsplit("/", 1)[-1] else 8080,
            http_secure="https" in url,
            grpc_host=os.environ.get("WEAVIATE_GRPC_HOST", "localhost"),
            grpc_port=int(os.environ.get("WEAVIATE_GRPC_PORT", "50051")),
            grpc_secure=False,
        )
        return client
    except ImportError:
        raise RuntimeError(
            "weaviate-client not installed. Add `weaviate-client>=4.0` to requirements.txt."
        )


# ─── Schema definitions ───────────────────────────────────────────────────────

# Each class has a `neo4j_id` (string, indexed) and `description` (text, vectorized).
WEAVIATE_CLASSES = [
    {
        "class": "LsigFunction",
        "description": "A function or method in the LSIG code graph.",
        "vectorizer": "text2vec-transformers",
        "properties": [
            {"name": "neo4j_id",    "dataType": ["text"], "tokenization": "field"},
            {"name": "description", "dataType": ["text"]},
            {"name": "service",     "dataType": ["text"], "tokenization": "word"},
            {"name": "language",    "dataType": ["text"], "tokenization": "word"},
        ],
    },
    {
        "class": "LsigEndpoint",
        "description": "An API endpoint in the LSIG code graph.",
        "vectorizer": "text2vec-transformers",
        "properties": [
            {"name": "neo4j_id",    "dataType": ["text"], "tokenization": "field"},
            {"name": "description", "dataType": ["text"]},
            {"name": "service",     "dataType": ["text"], "tokenization": "word"},
            {"name": "method",      "dataType": ["text"], "tokenization": "word"},
            {"name": "path",        "dataType": ["text"], "tokenization": "word"},
        ],
    },
    {
        "class": "LsigVulnerability",
        "description": "A security vulnerability in the LSIG graph.",
        "vectorizer": "text2vec-transformers",
        "properties": [
            {"name": "neo4j_id",    "dataType": ["text"], "tokenization": "field"},
            {"name": "description", "dataType": ["text"]},
            {"name": "cve_id",      "dataType": ["text"], "tokenization": "field"},
            {"name": "severity",    "dataType": ["text"], "tokenization": "word"},
        ],
    },
]

# ─── Text description builders ────────────────────────────────────────────────

def _function_description(fn: dict) -> str:
    parts = [fn.get("name", ""), f"in {fn.get('file', '')}", f"service={fn.get('service', '')}"]
    if fn.get("language"):
        parts.append(f"language={fn['language']}")
    if fn.get("owner_team"):
        parts.append(f"owner={fn['owner_team']}")
    return " | ".join(p for p in parts if p.strip())


def _endpoint_description(ep: dict) -> str:
    parts = [
        f"{ep.get('method', 'GET')} {ep.get('path', '/')}",
        f"service={ep.get('service', '')}",
    ]
    flags = []
    if ep.get("authenticated"):
        flags.append("authenticated")
    if ep.get("exposes_pii"):
        flags.append("exposes-PII")
    if ep.get("pci_scope"):
        flags.append("PCI-scoped")
    if ep.get("hipaa_scope"):
        flags.append("HIPAA-scoped")
    if flags:
        parts.append(" ".join(flags))
    if ep.get("owner_team"):
        parts.append(f"owner={ep['owner_team']}")
    return " | ".join(p for p in parts if p.strip())


def _vulnerability_description(v: dict) -> str:
    parts = [
        v.get("cve_id") or v.get("osv_id", ""),
        f"affects {v.get('affected_package', '')}",
        f"severity={v.get('severity', '')}",
        f"epss={v.get('epss_score', 0.0):.3f}",
    ]
    if v.get("in_kev"):
        parts.append("IN-KEV-confirmed-exploited")
    funcs = v.get("vulnerable_functions") or []
    if funcs:
        parts.append(f"vulnerable-functions: {' '.join(funcs[:5])}")
    return " | ".join(p for p in parts if p.strip())


# ─── Index class ─────────────────────────────────────────────────────────────

@dataclass
class SearchResult:
    neo4j_id: str
    description: str
    certainty: float    # 0.0–1.0 similarity score
    node_type: str      # "Function" | "APIEndpoint" | "Vulnerability"


class WeaviateIndex:
    """
    Manages the Weaviate vector index for LSIG graph nodes.
    Thread-safe for read operations; write operations are serialised by caller.
    """

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = with_retry(
                _weaviate_client, label="weaviate:connect", max_attempts=5,
                exceptions=(Exception,),
            )
        return self._client

    def ensure_schema(self) -> None:
        """Create Weaviate classes if they don't already exist."""
        client = self._get_client()
        existing = {c["class"] for c in client.schema.get()["classes"]}
        for cls_def in WEAVIATE_CLASSES:
            if cls_def["class"] not in existing:
                client.schema.create_class(cls_def)
                logger.info("Created Weaviate class: %s", cls_def["class"])

    def _upsert_batch(self, weaviate_class: str, objects: list[dict]) -> int:
        """Upsert a batch of objects into Weaviate. Returns count upserted."""
        if not objects:
            return 0
        client = self._get_client()
        collection = client.collections.get(weaviate_class)
        with collection.batch.dynamic() as batch:
            for obj in objects:
                neo4j_id = obj.get("neo4j_id", "")
                batch.add_object(properties=obj, uuid=_stable_uuid(neo4j_id))
        return len(objects)

    # ── Sync from Neo4j ───────────────────────────────────────────────────────

    def sync_functions(self, service: str | None = None, limit: int = 5000) -> int:
        """Index all (or service-specific) Function nodes from Neo4j."""
        svc_filter = "AND f.service = $svc" if service else ""
        params = {"svc": service} if service else {}
        rows = run_query(
            f"""
            MATCH (f:Function)
            WHERE f.deprecated_at IS NULL {svc_filter}
            RETURN f.id AS id, f.name AS name, f.file AS file,
                   f.service AS service, f.language AS language,
                   f.owner_team AS owner_team
            LIMIT {limit}
            """,
            params,
        )
        objects = [
            {
                "neo4j_id": r["id"],
                "description": _function_description(r),
                "service": r.get("service", ""),
                "language": r.get("language", ""),
            }
            for r in rows if r.get("id")
        ]
        count = self._upsert_batch("LsigFunction", objects)
        logger.info("Synced %d Functions to Weaviate", count)
        return count

    def sync_endpoints(self, service: str | None = None) -> int:
        """Index all (or service-specific) APIEndpoint nodes from Neo4j."""
        svc_filter = "AND e.service = $svc" if service else ""
        params = {"svc": service} if service else {}
        rows = run_query(
            f"""
            MATCH (e:APIEndpoint)
            WHERE e.deprecated_at IS NULL {svc_filter}
            RETURN e.id AS id, e.path AS path, e.method AS method,
                   e.service AS service, e.authenticated AS authenticated,
                   e.exposes_pii AS exposes_pii, e.pci_scope AS pci_scope,
                   e.hipaa_scope AS hipaa_scope, e.owner_team AS owner_team
            LIMIT 2000
            """,
            params,
        )
        objects = [
            {
                "neo4j_id": r["id"],
                "description": _endpoint_description(r),
                "service": r.get("service", ""),
                "method": r.get("method", ""),
                "path": r.get("path", ""),
            }
            for r in rows if r.get("id")
        ]
        count = self._upsert_batch("LsigEndpoint", objects)
        logger.info("Synced %d Endpoints to Weaviate", count)
        return count

    def sync_vulnerabilities(self) -> int:
        """Index all Vulnerability nodes from Neo4j."""
        rows = run_query(
            """
            MATCH (v:Vulnerability)
            WHERE v.deprecated_at IS NULL
            RETURN v.id AS id, v.cve_id AS cve_id, v.osv_id AS osv_id,
                   v.affected_package AS affected_package, v.severity AS severity,
                   v.epss_score AS epss_score, v.in_kev AS in_kev,
                   v.vulnerable_functions AS vulnerable_functions
            LIMIT 10000
            """
        )
        objects = [
            {
                "neo4j_id": r["id"],
                "description": _vulnerability_description(r),
                "cve_id": r.get("cve_id", ""),
                "severity": r.get("severity", ""),
            }
            for r in rows if r.get("id")
        ]
        count = self._upsert_batch("LsigVulnerability", objects)
        logger.info("Synced %d Vulnerabilities to Weaviate", count)
        return count

    def sync_from_neo4j(self, service: str | None = None) -> dict:
        """Full synchronisation of all node types from Neo4j into Weaviate."""
        self.ensure_schema()
        return {
            "functions": self.sync_functions(service),
            "endpoints": self.sync_endpoints(service),
            "vulnerabilities": self.sync_vulnerabilities(),
        }

    # ── Search ────────────────────────────────────────────────────────────────

    def _search(
        self,
        weaviate_class: str,
        node_type: str,
        query: str,
        limit: int,
        where_filter: dict | None = None,
    ) -> list[SearchResult]:
        client = self._get_client()
        collection = client.collections.get(weaviate_class)

        results = (
            collection.query
            .near_text(
                query=query,
                limit=limit,
                return_metadata=["certainty"],
            )
        )

        return [
            SearchResult(
                neo4j_id=obj.properties.get("neo4j_id", ""),
                description=obj.properties.get("description", ""),
                certainty=obj.metadata.certainty or 0.0,
                node_type=node_type,
            )
            for obj in results.objects
            if obj.properties.get("neo4j_id")
        ]

    def search_functions(
        self, query: str, limit: int = 10, service: str | None = None
    ) -> list[SearchResult]:
        """Semantic search over Function nodes."""
        where = (
            {"path": ["service"], "operator": "Equal", "valueText": service}
            if service else None
        )
        return self._search("LsigFunction", "Function", query, limit, where)

    def search_endpoints(
        self, query: str, limit: int = 10, service: str | None = None
    ) -> list[SearchResult]:
        """Semantic search over APIEndpoint nodes."""
        where = (
            {"path": ["service"], "operator": "Equal", "valueText": service}
            if service else None
        )
        return self._search("LsigEndpoint", "APIEndpoint", query, limit, where)

    def search_vulnerabilities(self, query: str, limit: int = 10) -> list[SearchResult]:
        """Semantic search over Vulnerability nodes."""
        return self._search("LsigVulnerability", "Vulnerability", query, limit)

    def search_all(self, query: str, limit: int = 5) -> list[SearchResult]:
        """Search across all three node types and merge results by score."""
        results: list[SearchResult] = []
        for fn in [self.search_functions, self.search_endpoints, self.search_vulnerabilities]:
            try:
                results.extend(fn(query=query, limit=limit))  # type: ignore[call-arg]
            except Exception as e:
                logger.debug("Search error in %s: %s", fn.__name__, e)
        results.sort(key=lambda r: r.certainty, reverse=True)
        return results[:limit * 2]

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None


# ─── UUID helpers ─────────────────────────────────────────────────────────────

def _stable_uuid(neo4j_id: str) -> str:
    """Generate a deterministic UUID5 from a Neo4j node ID."""
    import uuid
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # DNS namespace
    return str(uuid.uuid5(namespace, neo4j_id))


# ─── Module-level convenience ─────────────────────────────────────────────────

_default_index: WeaviateIndex | None = None


def get_index() -> WeaviateIndex:
    """Return the module-level WeaviateIndex singleton."""
    global _default_index
    if _default_index is None:
        _default_index = WeaviateIndex()
    return _default_index
