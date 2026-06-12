"""Telemetry — Prometheus metrics + structured logging.

The Prometheus metric names follow the ``vuln_intel_*`` convention
called out in the SREEngineer observability design (S1.9). The names
are deliberately namespaced so a single Prometheus server can host
multiple services without metric collisions.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry()

# --- ingestion metrics -------------------------------------------------------
vuln_intel_ingest_total = Counter(
    "vuln_intel_ingest_total",
    "CVE records ingested by source",
    ["source", "result"],  # result: new|merged|skipped
    registry=REGISTRY,
)
vuln_intel_ingest_duration_seconds = Histogram(
    "vuln_intel_ingest_duration_seconds",
    "Time spent ingesting from a single source",
    ["source"],
    registry=REGISTRY,
)
vuln_intel_source_up = Gauge(
    "vuln_intel_source_up",
    "1 if the upstream source responded on the last health probe, else 0",
    ["source"],
    registry=REGISTRY,
)
vuln_intel_records_stored = Gauge(
    "vuln_intel_records_stored",
    "Number of CVE records currently in the store",
    ["source"],
    registry=REGISTRY,
)

# --- scoring metrics ----------------------------------------------------------
vuln_intel_score_requests_total = Counter(
    "vuln_intel_score_requests_total",
    "Number of /score requests",
    ["kind"],
    registry=REGISTRY,
)
vuln_intel_match_findings = Counter(
    "vuln_intel_match_findings_total",
    "SBOM matches discovered by severity bucket",
    ["severity"],
    registry=REGISTRY,
)

# --- HTTP metrics ------------------------------------------------------------
vuln_intel_http_requests_total = Counter(
    "vuln_intel_http_requests_total",
    "HTTP requests served by the vuln-intel API",
    ["method", "path", "status"],
    registry=REGISTRY,
)
vuln_intel_http_request_duration_seconds = Histogram(
    "vuln_intel_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
    registry=REGISTRY,
)

# --- cache metrics ------------------------------------------------------------
vuln_intel_cache = Gauge(
    "vuln_intel_cache",
    "Cache hit ratio for a given source",
    ["source"],
    registry=REGISTRY,
)


def configure_logging(level: str = "INFO") -> None:
    """Configure stdlib + structlog logging in JSON format.

    Idempotent: safe to call multiple times (no duplicate handlers).
    """
    import structlog  # local import to keep cold-start light

    levelno = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    if getattr(root, "_vuln_intel_configured", False):
        root.setLevel(levelno)
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(),
            foreign_pre_chain=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
            ],
        )
    )
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(levelno)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    root._vuln_intel_configured = True  # type: ignore[attr-defined]


def get_logger(name: str) -> Any:
    """Return a stdlib logger — structlog is only used to format output."""
    return logging.getLogger(name)
