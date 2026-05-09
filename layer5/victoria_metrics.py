"""
Layer 5 — VictoriaMetrics Client.

Stores and retrieves time-series runtime call frequency history for:
  - Per-function call counts (24h, 7d rolling windows)
  - System-wide throughput (lsig_runtime_calls_per_second)
  - Certificate generation duration (p50/p95/p99)
  - CVE reachability reduction counts (lsig_cve_reachability_reductions_total)

VictoriaMetrics exposes a Prometheus-compatible remote_write endpoint and
a MetricsQL query endpoint. We use both:
  - remote_write for ingestion (from the Flink job and certificate engine)
  - query_range for retrieval (service_summary endpoint)

Usage:
    from layer5.victoria_metrics import VictoriaMetricsClient
    vm = VictoriaMetricsClient()
    vm.write_call_count("myapp", "handleLogin", call_count=450)
    history = vm.query_call_history("myapp", "handleLogin", days=7)
"""

from __future__ import annotations

import logging
import os
import time
import urllib.request
import urllib.parse
import json
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from layer1.retry_client import with_retry

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

def _vm_base_url() -> str:
    return os.environ.get("VICTORIAMETRICS_URL", "http://localhost:8428")


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class TimeSeries:
    metric_name: str
    labels: dict[str, str]
    timestamps: list[int]   # Unix seconds
    values: list[float]


@dataclass
class ScalarResult:
    value: float
    timestamp: int


# ─── Prometheus text format writer ────────────────────────────────────────────

def _format_prometheus_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    pairs = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{{{pairs}}}"


def _build_prometheus_line(
    metric_name: str,
    labels: dict[str, str],
    value: float,
    timestamp_ms: int | None = None,
) -> str:
    label_str = _format_prometheus_labels(labels)
    ts_str = f" {timestamp_ms}" if timestamp_ms is not None else ""
    return f"{metric_name}{label_str} {value}{ts_str}"


# ─── HTTP helpers ─────────────────────────────────────────────────────────────

def _http_post_raw(url: str, body: bytes, content_type: str) -> int:
    req = urllib.request.Request(url, data=body)
    req.add_header("Content-Type", content_type)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status


def _http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


# ─── VictoriaMetrics client ────────────────────────────────────────────────────

class VictoriaMetricsClient:
    """
    Thin client for VictoriaMetrics remote_write ingestion and MetricsQL queries.
    Falls back gracefully if VictoriaMetrics is not available.
    """

    def __init__(self, base_url: str | None = None):
        self._base = (base_url or _vm_base_url()).rstrip("/")

    # ── Write ─────────────────────────────────────────────────────────────────

    def write(self, lines: list[str]) -> bool:
        """
        Write Prometheus text format lines to VictoriaMetrics via /api/v1/import/prometheus.
        Returns True on success.
        """
        if not lines:
            return True
        body = "\n".join(lines).encode()
        url = f"{self._base}/api/v1/import/prometheus"

        def _post():
            status = _http_post_raw(url, body, "text/plain")
            if status not in (200, 204):
                raise RuntimeError(f"VictoriaMetrics returned HTTP {status}")

        try:
            with_retry(_post, label="victoriametrics:write", max_attempts=3,
                       exceptions=(Exception,))
            return True
        except Exception as e:
            logger.warning("VictoriaMetrics write failed: %s", e)
            return False

    def write_call_count(
        self,
        service: str,
        function_name: str,
        call_count: int,
        source_file: str = "",
    ) -> bool:
        """Record a 60-second call count observation for a function."""
        now_ms = int(time.time() * 1000)
        line = _build_prometheus_line(
            "lsig_function_calls_total",
            {"service": service, "function": function_name, "file": source_file},
            float(call_count),
            now_ms,
        )
        return self.write([line])

    def write_certificate_duration(self, pr_id: str, duration_ms: int) -> bool:
        """Record Change Impact Certificate generation duration."""
        line = _build_prometheus_line(
            "lsig_certificate_generation_duration_seconds",
            {"pr_id": pr_id},
            duration_ms / 1000.0,
        )
        return self.write([line])

    def write_cve_reachability_reduction(
        self, service: str, old_label: str, new_label: str
    ) -> bool:
        """Record a CVE being downgraded from CRITICAL by runtime evidence."""
        line = _build_prometheus_line(
            "lsig_cve_reachability_reductions_total",
            {"service": service, "from": old_label, "to": new_label},
            1.0,
        )
        return self.write([line])

    def write_code_graph_size(self, node_count: int, service: str = "") -> bool:
        """Record total node count in the code graph."""
        line = _build_prometheus_line(
            "lsig_code_graph_nodes_total",
            {"service": service} if service else {},
            float(node_count),
        )
        return self.write([line])

    # ── Query ─────────────────────────────────────────────────────────────────

    def query(self, metricsql: str) -> list[dict]:
        """Execute an instant MetricsQL query. Returns list of result series."""
        url = f"{self._base}/api/v1/query?" + urllib.parse.urlencode({"query": metricsql})
        try:
            data = with_retry(
                lambda: _http_get_json(url),
                label="victoriametrics:query",
                max_attempts=3,
                exceptions=(Exception,),
            )
            return data.get("data", {}).get("result", [])
        except Exception as e:
            logger.warning("VictoriaMetrics query failed: %s", e)
            return []

    def query_range(
        self,
        metricsql: str,
        start: datetime,
        end: datetime,
        step: str = "1h",
    ) -> list[TimeSeries]:
        """Execute a range MetricsQL query. Returns list of TimeSeries."""
        params = {
            "query": metricsql,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "step": step,
        }
        url = f"{self._base}/api/v1/query_range?" + urllib.parse.urlencode(params)
        try:
            data = with_retry(
                lambda: _http_get_json(url),
                label="victoriametrics:query_range",
                max_attempts=3,
                exceptions=(Exception,),
            )
            results = []
            for series in data.get("data", {}).get("result", []):
                metric = series.get("metric", {})
                values = series.get("values", [])
                ts = [int(v[0]) for v in values]
                vals = [float(v[1]) for v in values]
                results.append(TimeSeries(
                    metric_name=metric.get("__name__", ""),
                    labels={k: v for k, v in metric.items() if k != "__name__"},
                    timestamps=ts,
                    values=vals,
                ))
            return results
        except Exception as e:
            logger.warning("VictoriaMetrics range query failed: %s", e)
            return []

    def query_call_history(
        self,
        service: str,
        function_name: str,
        days: int = 7,
    ) -> TimeSeries | None:
        """
        Return the call count time series for a function over the last N days.
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)
        metricsql = (
            f'sum(increase(lsig_function_calls_total{{service="{service}",'
            f'function="{function_name}"}}[1h])) by (function)'
        )
        series = self.query_range(metricsql, start, now, step="1h")
        return series[0] if series else None

    def query_certificate_p95(self, days: int = 7) -> float | None:
        """Return p95 certificate generation duration in seconds over the last N days."""
        metricsql = (
            f"histogram_quantile(0.95, "
            f"sum(rate(lsig_certificate_generation_duration_seconds_bucket[{days}d])) "
            f"by (le))"
        )
        results = self.query(metricsql)
        if results and results[0].get("value"):
            try:
                return float(results[0]["value"][1])
            except (IndexError, ValueError):
                pass
        return None

    def query_false_positive_reduction_rate(self) -> float | None:
        """
        Compute the overall CVE false-positive reduction rate:
          total_reductions / total_cves_evaluated
        """
        reductions = self.query("sum(lsig_cve_reachability_reductions_total)")
        if not reductions or not reductions[0].get("value"):
            return None
        try:
            return float(reductions[0]["value"][1])
        except (IndexError, ValueError):
            return None

    def health(self) -> bool:
        """Return True if VictoriaMetrics is reachable."""
        try:
            _http_get_json(f"{self._base}/-/healthy")
            return True
        except Exception:
            return False


# ─── Module-level singleton ───────────────────────────────────────────────────

_client: VictoriaMetricsClient | None = None


def get_client() -> VictoriaMetricsClient:
    global _client
    if _client is None:
        _client = VictoriaMetricsClient()
    return _client
