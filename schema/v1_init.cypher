// LSIG v1 Schema — Layer 1 (Code Intelligence) through Layer 4 (Ownership + Data Flow)
// Apply with: cypher-shell -u neo4j -p lsig_dev < schema/v1_init.cypher

// ─── Constraints (enforce uniqueness and speed up lookups) ───────────────────

CREATE CONSTRAINT function_id IF NOT EXISTS
  FOR (f:Function) REQUIRE f.id IS UNIQUE;

CREATE CONSTRAINT module_id IF NOT EXISTS
  FOR (m:Module) REQUIRE m.id IS UNIQUE;

CREATE CONSTRAINT api_endpoint_id IF NOT EXISTS
  FOR (e:APIEndpoint) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT data_field_id IF NOT EXISTS
  FOR (d:DataField) REQUIRE d.id IS UNIQUE;

CREATE CONSTRAINT dependency_id IF NOT EXISTS
  FOR (dep:Dependency) REQUIRE dep.id IS UNIQUE;

CREATE CONSTRAINT vulnerability_id IF NOT EXISTS
  FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;

CREATE CONSTRAINT service_id IF NOT EXISTS
  FOR (s:Service) REQUIRE s.id IS UNIQUE;

CREATE CONSTRAINT external_endpoint_id IF NOT EXISTS
  FOR (e:ExternalEndpoint) REQUIRE e.id IS UNIQUE;

// ─── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX function_service IF NOT EXISTS FOR (f:Function) ON (f.service);
CREATE INDEX function_file IF NOT EXISTS FOR (f:Function) ON (f.file);
CREATE INDEX function_name IF NOT EXISTS FOR (f:Function) ON (f.name);
CREATE INDEX api_endpoint_service IF NOT EXISTS FOR (e:APIEndpoint) ON (e.service);
CREATE INDEX api_endpoint_path IF NOT EXISTS FOR (e:APIEndpoint) ON (e.path);
CREATE INDEX dependency_service IF NOT EXISTS FOR (d:Dependency) ON (d.service);
CREATE INDEX dependency_name IF NOT EXISTS FOR (d:Dependency) ON (d.name);
CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX data_field_service IF NOT EXISTS FOR (d:DataField) ON (d.service);

// ─── Node property types (documentation — Cypher is schema-optional) ─────────
//
// Function {
//   id: string          — "<service>:<file>:<name>:<line>"
//   name: string
//   file: string        — repo-relative path
//   line: integer
//   language: string    — "python" | "javascript" | "typescript" | "go" | "java" | "ruby"
//   service: string
//   owner_team: string
//   owner_email: string
//   deprecated_at: datetime | null
// }
//
// Module {
//   id: string          — "<service>:<path>"
//   name: string
//   path: string
//   service: string
//   deprecated_at: datetime | null
// }
//
// APIEndpoint {
//   id: string          — "<service>:<method>:<path>"
//   path: string
//   method: string      — HTTP verb or "SUBSCRIBE" / "PUBLISH" for async
//   service: string
//   authenticated: boolean
//   exposes_pii: boolean
//   owner_team: string
//   owner_email: string
//   deprecated_at: datetime | null
// }
//
// DataField {
//   id: string          — "<service>:<name>"
//   name: string
//   type: string
//   pii_likely: boolean
//   pii_type: string | null  — "EMAIL" | "SSN" | "PHONE" | "CREDIT_CARD" | etc.
//   service: string
//   deprecated_at: datetime | null
// }
//
// Dependency {
//   id: string          — "<service>:<ecosystem>:<name>:<version>"
//   name: string
//   version: string
//   ecosystem: string   — "pypi" | "npm" | "go" | "maven" | "gem"
//   service: string
//   deprecated_at: datetime | null
// }
//
// Vulnerability {
//   id: string          — cve_id or osv_id
//   cve_id: string | null
//   osv_id: string
//   affected_package: string
//   affected_versions: string[]
//   vulnerable_functions: string[]
//   severity: string    — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
//   epss_score: float
//   in_kev: boolean
//   published_at: datetime
//   deprecated_at: datetime | null
// }
//
// Service {
//   id: string          — service name
//   name: string
//   repo_url: string
//   language: string
//   regulatory_scope: string[]  — ["PCI", "HIPAA", "GDPR", "SOC2"]
//   deprecated_at: datetime | null
// }
//
// ExternalEndpoint {
//   id: string
//   url: string
//   service: string
//   discovered_at: datetime
//   deprecated_at: datetime | null
// }

// ─── Relationship types (documentation) ──────────────────────────────────────
//
// (Function)-[:CALLS]->(Function)
// (Function)-[:READS]->(DataField)
// (Function)-[:WRITES]->(DataField)
// (Module)-[:IMPORTS]->(Dependency)
// (APIEndpoint)-[:HANDLED_BY]->(Function)
// (Dependency)-[:HAS_VULN {severity, epss_score, in_kev, reachability}]->(Vulnerability)
// (Function)-[:RUNTIME_CALLS {last_seen, call_count_24h, call_count_7d}]->(Function)
// (DataField)-[:FLOWS_TO {via_endpoint, service_path}]->(DataField)
// (Service)-[:OWNS]->(Function)
// (Service)-[:OWNS]->(APIEndpoint)
// (Service)-[:OWNS]->(Module)
// (ExternalEndpoint)-[:MAPS_TO]->(APIEndpoint)

// ─── Seed the schema version marker ──────────────────────────────────────────
MERGE (sv:SchemaVersion {version: "1.0.0"})
  ON CREATE SET sv.applied_at = datetime(), sv.description = "Initial LSIG schema";
