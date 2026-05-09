import React, { useState } from "react";
import { searchAll } from "../api/lsig";

interface SearchResult {
  neo4j_id: string;
  description: string;
  certainty: number;
  node_type: string;
}

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await searchAll(query.trim());
      setResults(data.results || []);
    } catch (err: any) {
      setError(err.message || "Search failed");
    } finally {
      setLoading(false);
    }
  }

  const typeColor: Record<string, string> = {
    Function: "#3b82f6",
    APIEndpoint: "#10b981",
    Vulnerability: "#ef4444",
  };

  return (
    <div className="search-page">
      <h2>Semantic Search</h2>
      <form className="search-bar" onSubmit={handleSearch}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder='e.g. "authentication middleware" or "SQL injection vulnerability"'
          autoFocus
        />
        <button type="submit" disabled={loading}>
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

      {error && <div className="error">{error}</div>}

      {results.length > 0 && (
        <div className="results">
          {results.map(r => (
            <div key={r.neo4j_id} className="result-card card">
              <div className="result-header">
                <span
                  className="type-badge"
                  style={{ background: typeColor[r.node_type] || "#6b7280" }}
                >
                  {r.node_type}
                </span>
                <span className="certainty">{(r.certainty * 100).toFixed(0)}% match</span>
              </div>
              <div className="result-desc">{r.description}</div>
              <div className="result-id">{r.neo4j_id}</div>
            </div>
          ))}
        </div>
      )}

      {!loading && results.length === 0 && query && (
        <div className="empty">No results found for "{query}".</div>
      )}
    </div>
  );
}
