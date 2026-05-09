const GRAPH_API = import.meta.env.VITE_GRAPH_API_URL || "http://localhost:8005";
const CERT_API  = import.meta.env.VITE_CERT_API_URL  || "http://localhost:8006";

async function _get(url: string) {
  const res = await fetch(url);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HTTP ${res.status}: ${body}`);
  }
  return res.json();
}

async function _post(url: string, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

export function fetchServiceSummary(service: string) {
  return _get(`${GRAPH_API}/query/service_summary?service=${encodeURIComponent(service)}`);
}

export function fetchBlastRadius(service: string) {
  return _get(`${GRAPH_API}/viz/blast_radius?service=${encodeURIComponent(service)}`);
}

export function searchAll(query: string, limit = 10) {
  return _get(
    `${GRAPH_API}/search/all?q=${encodeURIComponent(query)}&limit=${limit}`
  );
}

export function nlQuery(question: string) {
  return _post(`${GRAPH_API}/query/nl`, { question });
}

export function fetchPRCertificate(prId: string) {
  return _get(`${CERT_API}/pr/${encodeURIComponent(prId)}/certificate`);
}

export function generateCertificate(body: {
  pr_id: string;
  service: string;
  changed_files: string[];
  repo_dir?: string;
}) {
  return _post(`${CERT_API}/certificate/generate`, body);
}

export function verifyCertificate(cert: Record<string, unknown>) {
  return _post(`${CERT_API}/certificate/verify`, { certificate: cert });
}
