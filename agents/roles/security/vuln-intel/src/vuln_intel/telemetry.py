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

# --- S2.7: feed refresh timestamp (lag SLO) ----------------------------------
# Single global gauge, labelled by source, used by the SREEngineer to
# alert on feed staleness. The value is the Unix timestamp (seconds)
# of the last successful ingest run; 0 means "never run". The
# service layer is responsible for setting this after every pull.
vuln_feed_last_refresh_timestamp_seconds = Gauge(
    "vuln_feed_last_refresh_timestamp_seconds",
    "Unix timestamp (seconds) of the last successful feed refresh, by source",
    ["source"],
    registry=REGISTRY,
)

# --- S2.8: validation + LLM + consensus metrics ------------------------------
vuln_intel_validation_rejected_total = Counter(
    "vuln_intel_validation_rejected_total",
    "Records rejected by the per-feed JSON-schema validator",
    ["source", "reason"],
    registry=REGISTRY,
)
vuln_intel_consensus_unofficial_total = Counter(
    "vuln_intel_consensus_unofficial_total",
    "CVE records tagged unofficial because HIGH/CRITICAL lacks cross-source consensus",
    registry=REGISTRY,
)
vuln_intel_llm_calls_total = Counter(
    "vuln_intel_llm_calls_total",
    "LLM exploit-scoring calls, by terminal status",
    ["status"],  # ok | schema_violation | budget_exceeded | transport_error | disabled
    registry=REGISTRY,
)
vuln_intel_llm_tokens_total = Counter(
    "vuln_intel_llm_tokens_total",
    "LLM tokens consumed, by tenant",
    ["tenant", "kind"],  # kind: prompt | completion
    registry=REGISTRY,
)
vuln_intel_llm_budget_remaining = Gauge(
    "vuln_intel_llm_budget_remaining",
    "Remaining LLM token budget (per-tenant, observed at last reset)",
    ["tenant"],
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
