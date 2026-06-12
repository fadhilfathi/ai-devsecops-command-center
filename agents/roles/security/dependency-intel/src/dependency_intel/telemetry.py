"""Telemetry for dependency-intel — Prometheus metrics + structured logging."""
from __future__ import annotations

import logging
import sys
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry()

dep_intel_graph_nodes = Gauge(
    "dep_intel_graph_nodes",
    "Number of nodes in the latest built graph",
    registry=REGISTRY,
)
dep_intel_graph_edges = Gauge(
    "dep_intel_graph_edges",
    "Number of edges in the latest built graph",
    registry=REGISTRY,
)
dep_intel_graphs_stored = Gauge(
    "dep_intel_graphs_stored",
    "Total number of graphs in the store",
    registry=REGISTRY,
)
dep_intel_correlation_total = Counter(
    "dep_intel_correlation_total",
    "Findings attached during correlation",
    ["severity"],
    registry=REGISTRY,
)
dep_intel_risk_compute_duration_seconds = Histogram(
    "dep_intel_risk_compute_duration_seconds",
    "Time spent computing risk propagation",
    registry=REGISTRY,
)
dep_intel_http_requests_total = Counter(
    "dep_intel_http_requests_total",
    "HTTP requests served by the dependency-intel API",
    ["method", "path", "status"],
    registry=REGISTRY,
)
dep_intel_http_request_duration_seconds = Histogram(
    "dep_intel_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
    registry=REGISTRY,
)
dep_intel_vuln_intel_up = Gauge(
    "dep_intel_vuln_intel_up",
    "1 if vuln-intel is reachable, else 0",
    registry=REGISTRY,
)


def configure_logging(level: str = "INFO") -> None:
    import structlog

    levelno = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    if getattr(root, "_dep_intel_configured", False):
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
    root._dep_intel_configured = True  # type: ignore[attr-defined]


def get_logger(name: str) -> Any:
    import structlog

    return structlog.get_logger(name)
