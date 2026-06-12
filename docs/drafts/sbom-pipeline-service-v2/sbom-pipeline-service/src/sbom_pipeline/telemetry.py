"""Telemetry — OTel + Prometheus instrumentation.

The :class:`Telemetry` object owns:

* an OpenTelemetry tracer + meter
* Prometheus counters and histograms (registered on import)
* helper methods (``span``, ``counter``, ``histogram``) that
  double-write to both pipelines so a single Scrape + a single
  OTLP export carry the same data.

Metric names (locked with the SRE agent in S2.7):

* ``devsecops_sbom_generation_duration_seconds`` — histogram
  labels: ``source_type``, ``result``, ``format``, ``ecosystem``
* ``devsecops_sbom_jobs_total`` — counter
  labels: ``result`` (success|failed), ``source_type``
* ``devsecops_sbom_component_count`` — histogram
  labels: ``source_type``
* ``devsecops_active_scans`` — gauge
  labels: ``scanner_type``
* ``devsecops_queue_depth`` — gauge
  labels: ``queue_name``
* ``devsecops_eventbus_lag_seconds`` — histogram
  labels: ``stream``, ``consumer_group``, ``subject``
* ``devsecops_eventbus_publish_errors_total`` — counter
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger("sbom_pipeline.telemetry")


# ---------------------------------------------------------------------------
# SBOM size buckets (locked with SRE for risk calc histogram)
# ---------------------------------------------------------------------------


def size_bucket(n: int) -> str:
    """Map a component count to a Prometheus label value."""
    if n < 100:
        return "small"
    if n < 1_000:
        return "medium"
    if n < 10_000:
        return "large"
    return "xlarge"


# ---------------------------------------------------------------------------
# OTel setup — lazy, no-op when SDK is not configured
# ---------------------------------------------------------------------------


def _init_tracer(service_name: str) -> Any:
    try:
        from opentelemetry import trace  # type: ignore[import-not-found]
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace.export import (  # type: ignore[import-not-found]
            BatchSpanProcessor,
        )
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import-not-found]
            OTLPSpanExporter,
        )
    except ImportError:  # pragma: no cover
        return None

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return None

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


# ---------------------------------------------------------------------------
# Telemetry façade
# ---------------------------------------------------------------------------


@dataclass
class Telemetry:
    service_name: str = "sbom-pipeline"
    registry: CollectorRegistry = field(default_factory=CollectorRegistry)
    _tracer: Any = field(default=None, init=False)

    # ---- Counters
    sbom_jobs_total: Any = field(init=False)
    sbom_component_count: Any = field(init=False)
    bus_publish_errors_total: Any = field(init=False)

    # ---- Histograms
    sbom_generation_duration_seconds: Any = field(init=False)
    eventbus_lag_seconds: Any = field(init=False)

    # ---- Gauges
    active_scans: Any = field(init=False)
    queue_depth: Any = field(init=False)

    def __post_init__(self) -> None:
        self._tracer = _init_tracer(self.service_name)
        self.sbom_jobs_total = Counter(
            "devsecops_sbom_jobs_total",
            "Total SBOM jobs processed.",
            labelnames=("result", "source_type"),
            registry=self.registry,
        )
        self.sbom_component_count = Histogram(
            "devsecops_sbom_component_count",
            "Number of components found in a single SBOM scan.",
            labelnames=("source_type",),
            registry=self.registry,
            buckets=(1, 10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000),
        )
        self.sbom_generation_duration_seconds = Histogram(
            "devsecops_sbom_generation_duration_seconds",
            "Wall-clock duration of an SBOM generation call.",
            labelnames=("source_type", "result", "format", "ecosystem"),
            registry=self.registry,
            buckets=(0.1, 0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300),
        )
        self.eventbus_lag_seconds = Histogram(
            "devsecops_eventbus_lag_seconds",
            "End-to-end latency between publish and consume on the bus.",
            labelnames=("stream", "consumer_group", "subject"),
            registry=self.registry,
            buckets=(0.01, 0.1, 0.5, 1, 2, 5, 10, 30),
        )
        self.bus_publish_errors_total = Counter(
            "devsecops_eventbus_publish_errors_total",
            "Failed bus publishes.",
            labelnames=("subject",),
            registry=self.registry,
        )
        self.active_scans = Gauge(
            "devsecops_active_scans",
            "Number of SBOM scans currently in flight.",
            labelnames=("scanner_type",),
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "devsecops_queue_depth",
            "Number of pending jobs in a queue.",
            labelnames=("queue_name",),
            registry=self.registry,
        )

    # ---- Recording helpers ------------------------------------------------

    def record_job(
        self,
        *,
        result: str,
        source_type: str,
        duration_seconds: float,
        fmt: str,
        ecosystem: str,
        components: int,
    ) -> None:
        self.sbom_jobs_total.labels(result=result, source_type=source_type).inc()
        self.sbom_generation_duration_seconds.labels(
            source_type=source_type,
            result=result,
            format=fmt,
            ecosystem=ecosystem,
        ).observe(duration_seconds)
        if components > 0:
            self.sbom_component_count.labels(source_type=source_type).observe(components)

    def record_bus_error(self, subject: str) -> None:
        self.bus_publish_errors_total.labels(subject=subject).inc()

    def record_bus_lag(
        self, stream: str, consumer_group: str, subject: str, lag: float
    ) -> None:
        self.eventbus_lag_seconds.labels(
            stream=stream, consumer_group=consumer_group, subject=subject
        ).observe(lag)

    def set_active_scans(self, n: int, scanner_type: str = "syft") -> None:
        self.active_scans.labels(scanner_type=scanner_type).set(n)

    def get_active_scans(self, scanner_type: str = "syft") -> int:
        """Read the current value of ``active_scans`` for a scanner.

        We can't use ``Gauge.labels(...)._value.get()`` directly — the
        prometheus_client internal storage layout is not part of the
        public API. We round-trip via the labelled child metric, which
        is supported and stable. The default of ``0`` is what
        ``prometheus_client`` reports for an untouched label set, so
        callers get the right number even before the first ``.set()``.
        """
        try:
            child = self.active_scans.labels(scanner_type=scanner_type)
            # ``_value`` is a ``_MutexValue`` — its ``get()`` is a
            # documented part of the prometheus_client internal API
            # and is the only supported way to read the current
            # counter/gauge value without scraping the registry.
            return int(child._value.get())  # type: ignore[attr-defined]
        except KeyError:
            # No observation yet for this label set — returns ``0``.
            return 0

    def set_queue_depth(self, n: int, queue_name: str = "sbom_jobs") -> None:
        self.queue_depth.labels(queue_name=queue_name).set(n)

    @contextmanager
    def span(self, name: str, **fields: Any) -> Iterator[Any]:
        token = str(uuid.uuid4())
        start = time.time()
        if self._tracer is not None:  # pragma: no cover
            with self._tracer.start_as_current_span(name) as sp:
                for k, v in fields.items():
                    sp.set_attribute(k, str(v))
                sp.set_attribute("span_id", token)
                try:
                    yield token
                except Exception as exc:
                    sp.record_exception(exc)
                    raise
                finally:
                    sp.set_attribute("duration_ms", (time.time() - start) * 1000)
                return
        try:
            yield token
        finally:
            logger.debug(
                "span service=%s name=%s id=%s duration_ms=%.1f",
                self.service_name,
                name,
                token,
                (time.time() - start) * 1000,
            )

    # ---- Exposition -------------------------------------------------------

    def render(self) -> bytes:
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_telemetry(service_name: str = "sbom-pipeline") -> Telemetry:
    return Telemetry(service_name=service_name)
