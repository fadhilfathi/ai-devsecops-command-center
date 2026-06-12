"""
SRE-defined observability toolkit for Python services in the AI-DevSecOps
Command Center.

Mirror of the TypeScript reference at `backend/common/observability/` (otel.ts,
logger.ts, health.ts). This package is the canonical SRE target for the three
Sprint 2 Python services:

  - sbom-pipeline         (port 4007)
  - vuln-intel            (port 4008)
  - dependency-intel      (port 4009)

Submodules
----------
otel     — OpenTelemetry SDK bootstrap (traces, metrics, logs) + W3C context
logger   — structlog-based structured JSON logger with PII redaction
health   — FastAPI health-check server with /healthz, /readyz, /startz
metrics  — Prometheus client helpers, standard metric definitions, the
           devsecops_<service>_<metric>_<unit> convention, and a shared
           REGISTRY so multiple modules emit to the same /metrics endpoint.
"""
from .otel import start_otel, shutdown_otel
from .logger import create_logger, with_tenant, with_user
from .health import build_health_app
from .metrics import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    http_request_duration_seconds,
    http_requests_total,
    http_requests_in_flight,
    sbom_generation_duration_seconds,
    vulnerability_ingestion_total,
    risk_calculation_duration_seconds,
    active_scans,
    queue_depth,
    eventbus_lag_seconds,
)

__all__ = [
    "start_otel",
    "shutdown_otel",
    "create_logger",
    "with_tenant",
    "with_user",
    "build_health_app",
    "REGISTRY",
    "Counter",
    "Gauge",
    "Histogram",
    "http_request_duration_seconds",
    "http_requests_total",
    "http_requests_in_flight",
    "sbom_generation_duration_seconds",
    "vulnerability_ingestion_total",
    "risk_calculation_duration_seconds",
    "active_scans",
    "queue_depth",
    "eventbus_lag_seconds",
]
