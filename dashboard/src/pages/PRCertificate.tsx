import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import RiskBadge from "../components/RiskBadge";
import { fetchPRCertificate, generateCertificate } from "../api/lsig";

interface Certificate {
  certificate_id: string;
  pr_id: string;
  service: string;
  generated_at: string;
  generation_duration_ms: number;
  risk_level: string;
  narrative: string;
  changed_functions: Array<{
    function_id: string;
    function_name: string;
    file: string;
    owner_team: string;
    callers_count: number;
    runtime_callers_count: number;
    is_endpoint_handler: boolean;
  }>;
  blast_radius: {
    direct_callers: string[];
    transitive_callers: string[];
    affected_endpoints: string[];
    affected_services: string[];
  };
  security_delta: {
    new_critical_vulns: Array<{ cve_id: string; severity: string; epss_score: number; in_kev: boolean }>;
    pii_flows_added: Array<{ source_field: string; pii_type: string; dest_service: string; unregulated: boolean }>;
    net_risk_change: string;
  };
  signature: string;
}

export default function PRCertificate() {
  const { prId } = useParams<{ prId: string }>();
  const navigate = useNavigate();
  const [prInput, setPrInput] = useState(prId ? decodeURIComponent(prId) : "");
  const [cert, setCert] = useState<Certificate | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generate mode
  const [genService, setGenService] = useState("");
  const [genFiles, setGenFiles] = useState("");
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    if (prId) {
      loadCert(decodeURIComponent(prId));
    }
  }, [prId]);

  async function loadCert(id: string) {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPRCertificate(id);
      setCert(data);
    } catch (e: any) {
      setError(e.message || "Certificate not found");
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    setGenerating(true);
    setError(null);
    try {
      const files = genFiles.split("\n").map(f => f.trim()).filter(Boolean);
      const data = await generateCertificate({
        pr_id: prInput,
        service: genService,
        changed_files: files,
      });
      setCert(data);
      navigate(`/pr/${encodeURIComponent(prInput)}`);
    } catch (e: any) {
      setError(e.message || "Generation failed");
    } finally {
      setGenerating(false);
    }
  }

  const riskColor: Record<string, string> = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#ca8a04",
    LOW: "#16a34a",
    NONE: "#6b7280",
  };

  return (
    <div className="pr-view">
      <div className="pr-lookup">
        <form onSubmit={e => { e.preventDefault(); navigate(`/pr/${encodeURIComponent(prInput)}`); }}>
          <input
            value={prInput}
            onChange={e => setPrInput(e.target.value)}
            placeholder="PR ID (e.g. github:myorg/repo:PR-42)"
          />
          <button type="submit">Load</button>
        </form>
      </div>

      {!cert && (
        <div className="generate-form card">
          <h3>Generate Certificate</h3>
          <form onSubmit={handleGenerate}>
            <label>PR ID<input value={prInput} onChange={e => setPrInput(e.target.value)} placeholder="github:myorg/repo:PR-42" /></label>
            <label>Service<input value={genService} onChange={e => setGenService(e.target.value)} placeholder="auth" /></label>
            <label>
              Changed files (one per line)
              <textarea
                value={genFiles}
                onChange={e => setGenFiles(e.target.value)}
                rows={4}
                placeholder={"auth/jwt.py\nauth/models.py"}
              />
            </label>
            <button type="submit" disabled={generating}>
              {generating ? "Generating…" : "Generate Certificate"}
            </button>
          </form>
        </div>
      )}

      {loading && <div className="loading">Loading certificate…</div>}
      {error && <div className="error">{error}</div>}

      {cert && (
        <div className="certificate">
          <div className="cert-header">
            <div>
              <h2>{cert.pr_id}</h2>
              <div className="cert-meta">
                {cert.certificate_id} · {new Date(cert.generated_at).toLocaleString()} ·
                {cert.generation_duration_ms}ms
              </div>
            </div>
            <div className="risk-badge" style={{ background: riskColor[cert.risk_level] }}>
              {cert.risk_level}
            </div>
          </div>

          <div className="narrative card">
            <p>{cert.narrative}</p>
          </div>

          <div className="cert-grid">
            <div className="card">
              <h3>Changed Functions ({cert.changed_functions.length})</h3>
              <table>
                <thead>
                  <tr><th>Function</th><th>File</th><th>Owner</th><th>Callers</th><th>EP?</th></tr>
                </thead>
                <tbody>
                  {cert.changed_functions.map(f => (
                    <tr key={f.function_id}>
                      <td>{f.function_name}</td>
                      <td className="file">{f.file}</td>
                      <td>{f.owner_team}</td>
                      <td>{f.callers_count} / {f.runtime_callers_count}</td>
                      <td>{f.is_endpoint_handler ? "✓" : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card">
              <h3>Blast Radius</h3>
              <div className="stat">{cert.blast_radius.transitive_callers.length} <span>callers (depth ≤5)</span></div>
              <div className="stat">{cert.blast_radius.affected_endpoints.length} <span>endpoints</span></div>
              <div className="stat">{cert.blast_radius.affected_services.length} <span>services</span></div>
              {cert.blast_radius.affected_services.length > 0 && (
                <div className="service-list">
                  {cert.blast_radius.affected_services.map(s => (
                    <span key={s} className="service-tag">{s}</span>
                  ))}
                </div>
              )}
            </div>

            {cert.security_delta.new_critical_vulns.length > 0 && (
              <div className="card">
                <h3>CVEs in Scope ({cert.security_delta.new_critical_vulns.length})</h3>
                {cert.security_delta.new_critical_vulns.map(v => (
                  <div key={v.cve_id} className="vuln-row">
                    <span className={`sev-badge sev-${v.severity.toLowerCase()}`}>{v.severity}</span>
                    <span className="cve-id">{v.cve_id}</span>
                    <span className="epss">EPSS {(v.epss_score * 100).toFixed(1)}%</span>
                    {v.in_kev && <span className="kev-badge">KEV</span>}
                  </div>
                ))}
              </div>
            )}

            {cert.security_delta.pii_flows_added.length > 0 && (
              <div className="card">
                <h3>PII Flows Affected ({cert.security_delta.pii_flows_added.length})</h3>
                {cert.security_delta.pii_flows_added.map((p, i) => (
                  <div key={i} className={`pii-row ${p.unregulated ? "unregulated" : ""}`}>
                    <span>{p.source_field}</span>
                    <span className="pii-type">{p.pii_type}</span>
                    <span>→ {p.dest_service}</span>
                    {p.unregulated && <span className="warn">UNREGULATED</span>}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="cert-footer">
            <span className="sig">Signature: <code>{cert.signature.slice(0, 16)}…</code></span>
            <button onClick={() => navigator.clipboard.writeText(JSON.stringify(cert, null, 2))}>
              Copy JSON
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
