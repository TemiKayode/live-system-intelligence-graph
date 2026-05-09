import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import CytoscapeGraph from "../components/CytoscapeGraph";
import RiskBadge from "../components/RiskBadge";
import { fetchServiceSummary, fetchBlastRadius } from "../api/lsig";

interface ServiceSummary {
  service: string;
  code_graph: {
    total_functions: number;
    deprecated_functions: number;
    total_endpoints: number;
    pii_endpoints: number;
    unauth_endpoints: number;
  };
  security: Array<{ severity: string; count: number; in_kev_count: number }>;
  ownership: Array<{ owner_team: string; function_count: number }>;
  runtime: {
    hot_paths: number;
    dead_code_functions: number;
  };
}

export default function ServiceView() {
  const { service } = useParams<{ service: string }>();
  const navigate = useNavigate();
  const [serviceInput, setServiceInput] = useState(service || "");
  const [summary, setSummary] = useState<ServiceSummary | null>(null);
  const [graphData, setGraphData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (service) {
      loadService(service);
    }
  }, [service]);

  async function loadService(svc: string) {
    setLoading(true);
    setError(null);
    try {
      const [sum, graph] = await Promise.all([
        fetchServiceSummary(svc),
        fetchBlastRadius(svc),
      ]);
      setSummary(sum);
      setGraphData(graph);
    } catch (e: any) {
      setError(e.message || "Failed to load service");
    } finally {
      setLoading(false);
    }
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (serviceInput.trim()) {
      navigate(`/service/${serviceInput.trim()}`);
    }
  }

  const criticalVulns = summary?.security.find(s => s.severity === "CRITICAL");
  const highVulns = summary?.security.find(s => s.severity === "HIGH");

  return (
    <div className="service-view">
      <form className="search-bar" onSubmit={handleSearch}>
        <input
          value={serviceInput}
          onChange={e => setServiceInput(e.target.value)}
          placeholder="Service name (e.g. auth, payments)"
        />
        <button type="submit">Load</button>
      </form>

      {loading && <div className="loading">Loading…</div>}
      {error && <div className="error">{error}</div>}

      {summary && (
        <div className="summary-grid">
          <div className="card">
            <h3>Code Graph</h3>
            <div className="stat">{summary.code_graph.total_functions} <span>functions</span></div>
            <div className="stat">{summary.code_graph.total_endpoints} <span>endpoints</span></div>
            <div className="stat warning">{summary.code_graph.pii_endpoints} <span>PII endpoints</span></div>
            <div className="stat warning">{summary.code_graph.unauth_endpoints} <span>unauthenticated</span></div>
          </div>

          <div className="card">
            <h3>Security</h3>
            {criticalVulns && (
              <div className="stat critical">
                {criticalVulns.count} <span>CRITICAL CVEs</span>
                {criticalVulns.in_kev_count > 0 && (
                  <span className="kev-badge"> ({criticalVulns.in_kev_count} KEV)</span>
                )}
              </div>
            )}
            {highVulns && (
              <div className="stat high">{highVulns.count} <span>HIGH CVEs</span></div>
            )}
            {!criticalVulns && !highVulns && (
              <div className="stat ok">No critical/high CVEs</div>
            )}
          </div>

          <div className="card">
            <h3>Ownership</h3>
            {summary.ownership.slice(0, 5).map(o => (
              <div key={o.owner_team} className="owner-row">
                <span className="team">{o.owner_team}</span>
                <span className="count">{o.function_count} fns</span>
              </div>
            ))}
          </div>

          <div className="card">
            <h3>Runtime</h3>
            <div className="stat">{summary.runtime.hot_paths} <span>hot paths</span></div>
            <div className="stat muted">{summary.runtime.dead_code_functions} <span>dead code</span></div>
          </div>
        </div>
      )}

      {graphData && (
        <div className="graph-section">
          <h3>Blast Radius Graph</h3>
          <CytoscapeGraph data={graphData} />
        </div>
      )}
    </div>
  );
}
