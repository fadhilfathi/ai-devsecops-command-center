# =============================================================================
# OpenTelemetry bootstrap — Python reference (Sprint 2)
# Owner: SREEngineer
# See: docs/observability/monitoring-architecture.md §3, §7
#
# Mirror of backend/common/observability/otel.ts.
#
# Initializes:
#   - Resource attributes (service.name, service.version, deployment.environment)
#   - Trace exporter (OTLP gRPC -> OTel Collector)
#   - Metric exporter (OTLP -> Collector)
#   - Log exporter (OTLP -> Collector) — structlog bridge
#   - Auto-instrumentations for FastAPI, httpx, SQLite, requests, urllib3
# =============================================================================

from __future__ import annotations

import os
import signal
import threading
from typing import Literal

from opentelemetry import trace, metrics, logs
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.log_exporter import OTLPLogExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.logs import LoggerProvider
from opentelemetry.sdk.logs.export import BatchLogRecordProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor

_lock = threading.Lock()
_started = False
_shutdown_hooks_installed = False

EnvName = Literal["dev", "staging", "prod"]


def _resource(service: str, version: str, env: EnvName) -> Resource:
    return Resource.create(
        {
            SERVICE_NAME: service,
            SERVICE_VERSION: version,
            "deployment.environment": env,
            "service.namespace": "ai-devsecops",
            "tenant.id": os.getenv("TENANT_ID", "default"),
        }
    )


def _excluded_urls() -> tuple[str, ...]:
    """
    Endpoints that should never be traced. Same exclusions as the TypeScript
    reference in backend/common/observability/otel.ts.
    """
    return ("/healthz", "/readyz", "/startz", "/metrics")


def start_otel(
    service: str,
    version: str,
    env: EnvName = "dev",
    endpoint: str | None = None,
) -> None:
    """
    Initialize the OpenTelemetry SDK. Safe to call once per process; subsequent
    calls are no-ops.

    Parameters
    ----------
    service : str
        Logical service name (e.g., "sbom-pipeline"). Must match
        `^[a-z][a-z0-9-]{1,63}$`.
    version : str
        Semantic version of the binary (e.g., "1.0.0").
    env : "dev" | "staging" | "prod"
        Deployment environment.
    endpoint : str, optional
        OTLP gRPC endpoint. Defaults to OTEL_EXPORTER_OTLP_ENDPOINT or
        "http://localhost:4317".
    """
    global _started
    with _lock:
        if _started:
            return
        if not service or not _SERVICE_RE.match(service):
            raise ValueError(
                f"Invalid service name: {service!r}. "
                "Must match ^[a-z][a-z0-9-]{1,63}$."
            )

        otlp_endpoint = endpoint or os.getenv(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
        )
        resource = _resource(service, version, env)

        # --- Traces ---
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True))
        )
        trace.set_tracer_provider(tracer_provider)

        # --- Metrics ---
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True),
            export_interval_millis=15_000,
        )
        meter_provider = MeterProvider(
            resource=resource, metric_readers=[metric_reader]
        )
        metrics.set_meter_provider(meter_provider)

        # --- Logs ---
        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(OTLPLogExporter(endpoint=otlp_endpoint, insecure=True))
        )
        logs.set_logger_provider(logger_provider)

        # --- Auto-instrumentations ---
        # We deliberately *do not* trace probe endpoints; the FastAPI hook
        # receives the URL via the `excluded_urls` arg.
        try:
            FastAPIInstrumentor().instrument(excluded_urls=_excluded_urls())
        except Exception:  # pragma: no cover — instrumentation may already be loaded
            pass
        HTTPXClientInstrumentor().instrument()
        RequestsInstrumentor().instrument(excluded_urls=_excluded_urls())
        URLLib3Instrumentor().instrument()
        SQLite3Instrumentor().instrument()

        _started = True
        _install_shutdown_hooks()
        # Last-line breadcrumb so the process log shows the init.
        print(
            f'{{"timestamp":"{_iso_now()}","level":"info","service":"{service}",'
            f'"version":"{version}","env":"{env}",'
            f'"message":"OpenTelemetry started","context":'
            f'{{"endpoint":"{otlp_endpoint}"}}}}'
        )


def shutdown_otel() -> None:
    """Flush all telemetry and shut down the SDK providers."""
    try:
        # Each provider may be None if start_otel wasn't called; tolerate.
        tp = trace.get_tracer_provider()
        if hasattr(tp, "shutdown"):
            tp.shutdown()
        mp = metrics.get_meter_provider()
        if hasattr(mp, "shutdown"):
            mp.shutdown()
        lp = logs.get_logger_provider()
        if hasattr(lp, "shutdown"):
            lp.shutdown()
    except Exception as exc:  # pragma: no cover
        print(
            f'{{"timestamp":"{_iso_now()}","level":"error",'
            f'"message":"OpenTelemetry shutdown failed",'
            f'"context":{{"error":"{exc}"}}}}'
        )


def _install_shutdown_hooks() -> None:
    """Install SIGTERM/SIGINT handlers that flush telemetry before exit."""
    global _shutdown_hooks_installed
    if _shutdown_hooks_installed:
        return
    _shutdown_hooks_installed = True

    def _handler(signum, _frame):
        shutdown_otel()
        # Re-raise default behavior
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):  # not main thread / unsupported platform
            pass


# --- helpers ---
import re
import datetime as _dt

_SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")


def _iso_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
