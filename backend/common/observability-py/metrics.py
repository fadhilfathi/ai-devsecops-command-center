# =============================================================================
# Prometheus metrics — Python reference (Sprint 2)
# Owner: SREEngineer
# See: docs/observability/monitoring-architecture.md §4
#       infra/observability/prometheus/cardinality_lint.py
#
# Uses the `prometheus_client` library. Exposes a shared REGISTRY so multiple
# modules can declare metrics that all end up on the same /metrics endpoint.
#
# Naming convention: devsecops_<service>_<metric>_<unit>
# Cardinality budgets enforced by the CI lint in
#   infra/observability/prometheus/cardinality_lint.py
# =============================================================================

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from prometheus_client.exposition import REGISTRY as _DEFAULT_REGISTRY

# Allow tests to inject a fresh registry; in production we use the default.
REGISTRY: CollectorRegistry = _DEFAULT_REGISTRY


# ---------------------------------------------------------------------------
# Standard HTTP metrics — available to all services
# ---------------------------------------------------------------------------
http_request_duration_seconds = Histogram(
    "devsecops_http_request_duration_seconds",
    "Duration of HTTP requests in seconds, by service/route/method/status_class.",
    labelnames=("service", "route", "method", "status_class"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=REGISTRY,
)

http_requests_total = Counter(
    "devsecops_http_requests_total",
    "Total HTTP requests, by service/route/method/status_class.",
    labelnames=("service", "route", "method", "status_class"),
    registry=REGISTRY,
)

http_requests_in_flight = Gauge(
    "devsecops_http_requests_in_flight",
    "Number of HTTP requests currently being handled.",
    labelnames=("service",),
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# Sprint 2 — Security stack metrics
# Label sets and allowed values LOCKED by PlatformArchitect (S2.7 spec).
# Source of truth: docs/observability/metrics-spec.md (PlatformArchitect).
# Cardinality budgets enforced by infra/observability/prometheus/cardinality_lint.py.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# sbom_generation_duration_seconds
# Locked labels: {source_type, ecosystem, target_type, result}
# Allowed values:
#   source_type  : syft | dependency_track | import | manual
#   ecosystem    : npm | pypi | maven | nuget | go | cargo | rubygems | composer
#                | conan | apk | deb | rpm | generic
#   target_type  : image | filesystem | repo | archive | directory
#   result       : success | failure | timeout | cancelled
# Cardinality: 4 × 14 × 5 × 4 = 1,120 label combinations × ~12 buckets = ~13,440 series.
# ---------------------------------------------------------------------------
sbom_generation_duration_seconds = Histogram(
    "devsecops_sbom_generation_duration_seconds",
    "SBOM generation duration in seconds.",
    labelnames=("service", "source_type", "ecosystem", "target_type", "result"),
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600),
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# vulnerability_ingestion_total
# Locked labels: {source, severity}
# Allowed values:
#   source    : nvd | ghsa | osv
#   severity  : critical | high | medium | low | unknown
# Cardinality: 3 × 5 = 15 label combinations per service. Tiny.
# ---------------------------------------------------------------------------
vulnerability_ingestion_total = Counter(
    "devsecops_vulnerability_ingestion_total",
    "Vulnerabilities ingested, by feed source and severity.",
    labelnames=("service", "source", "severity"),
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# risk_calculation_duration_seconds
# Locked labels: {sbom_size_bucket, algorithm, result}
# Allowed values:
#   sbom_size_bucket : small | medium | large | xlarge | xxlarge
#   algorithm        : cvss_only | cvss_epss | cvss_epss_kev | full
#   result           : success | failure | timeout | cancelled
# Buckets (5): small<100, medium 100-999, large 1k-9.9k,
#              xlarge 10k-49.9k, xxlarge >=50k
# Cardinality: 5 × 4 × 4 = 80 label combinations per service. Far under budget.
# ---------------------------------------------------------------------------
risk_calculation_duration_seconds = Histogram(
    "devsecops_risk_calculation_duration_seconds",
    "Risk calculation duration, bucketed by SBOM size and algorithm.",
    labelnames=("service", "sbom_size_bucket", "algorithm", "result"),
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300),
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# active_scans
# Locked labels: {scanner_type}
# Allowed values: syft | grype | trivy | dependency_track
# Cardinality: ~4 per service. Tiny.
# ---------------------------------------------------------------------------
active_scans = Gauge(
    "devsecops_active_scans",
    "Number of scans currently in progress, by scanner type.",
    labelnames=("service", "scanner_type"),
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# queue_depth
# Locked labels: {queue_name}
# Allowed values: sbom_jobs | cve_processing | risk_calc_jobs | ...
# Cardinality: ~4 per service.
# ---------------------------------------------------------------------------
queue_depth = Gauge(
    "devsecops_queue_depth",
    "Pending work items in a queue.",
    labelnames=("service", "queue_name"),
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# eventbus_lag_seconds (PlatformArchitect owns; emitted by all services)
# Locked labels: {stream, consumer_group, subject}
# Buckets (SLO-shaped): 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300
# Consumed by platform SLI: platform:event_bus:lag:p99
# Cardinality: ~3 services × ~5 streams × ~3 consumer_groups × ~10 subjects
#              = ~450 series (within 5000 budget).
# ---------------------------------------------------------------------------
eventbus_lag_seconds = Histogram(
    "devsecops_eventbus_lag_seconds",
    "End-to-end event bus lag in seconds (publish to consume).",
    labelnames=("service", "stream", "consumer_group", "subject"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300),
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# Helper: size-bucket a SBOM's component count
# Locked by PlatformArchitect: 5 buckets.
#   small    : < 100
#   medium   : 100 – 999
#   large    : 1,000 – 9,999
#   xlarge   : 10,000 – 49,999
#   xxlarge  : >= 50,000
# ---------------------------------------------------------------------------
def sbom_size_bucket(component_count: int) -> str:
    if component_count < 100:
        return "small"
    if component_count < 1_000:
        return "medium"
    if component_count < 10_000:
        return "large"
    if component_count < 50_000:
        return "xlarge"
    return "xxlarge"


# ---------------------------------------------------------------------------
# /metrics exposition helper
# ---------------------------------------------------------------------------
def render_metrics() -> tuple[bytes, str]:
    """Return (body, content_type) for a FastAPI /metrics endpoint."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
