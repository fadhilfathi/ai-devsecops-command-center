"""Telemetry and observability for the SBOM generator.

The module is intentionally lightweight — it does not couple to a
specific OpenTelemetry SDK or Prometheus client. The default exporter
writes JSON lines to stdout, which the platform's log forwarder
ingests. To switch exporters, supply a different ``telemetry`` object
to the service factory.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sbom_generator.telemetry")


@dataclass
class Telemetry:
    """In-memory telemetry buffer + stdout JSON exporter."""

    service_name: str
    started_at: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    counters: Dict[str, int] = field(default_factory=dict)
    histograms: Dict[str, List[float]] = field(default_factory=dict)
    gauges: Dict[str, float] = field(default_factory=dict)

    def inc(self, name: str, value: int = 1, **labels: Any) -> None:
        key = self._labeled(name, labels)
        self.counters[key] = self.counters.get(key, 0) + value
        self._emit("counter", name, value, labels)

    def observe(self, name: str, value: float, **labels: Any) -> None:
        key = self._labeled(name, labels)
        self.histograms.setdefault(key, []).append(value)
        self._emit("histogram", name, value, labels)

    def gauge(self, name: str, value: float, **labels: Any) -> None:
        key = self._labeled(name, labels)
        self.gauges[key] = value
        self._emit("gauge", name, value, labels)

    def event(self, name: str, **fields: Any) -> None:
        payload = {
            "type": "event",
            "event": name,
            "service": self.service_name,
            "ts": time.time(),
            "fields": fields,
        }
        self.events.append(payload)
        logger.info("event %s :: %s", name, json.dumps(fields, default=str))

    @contextmanager
    def span(self, name: str, **fields: Any):
        token = str(uuid.uuid4())
        start = time.time()
        logger.info(
            "span.begin service=%s name=%s id=%s fields=%s",
            self.service_name,
            name,
            token,
            json.dumps(fields, default=str),
        )
        try:
            yield token
        except Exception as exc:  # noqa: BLE001
            self.event(
                f"{name}.error",
                span_id=token,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            raise
        else:
            duration = time.time() - start
            self.observe(f"{name}.duration_ms", duration * 1000)
            self.event(f"{name}.end", span_id=token, duration_ms=duration * 1000)

    def render_prometheus(self) -> str:
        """Render a minimal Prometheus text-format exposition."""
        lines: List[str] = []
        for key, value in self.counters.items():
            metric = key.split("{", 1)[0]
            labels = self._render_labels(key)
            lines.append(f"# TYPE {metric} counter")
            lines.append(f"{metric}{labels} {value}")
        for key, samples in self.histograms.items():
            metric = key.split("{", 1)[0]
            labels = self._render_labels(key)
            lines.append(f"# TYPE {metric} summary")
            for s in samples[-10:]:
                lines.append(f"{metric}{labels} {s}")
        for key, value in self.gauges.items():
            metric = key.split("{", 1)[0]
            labels = self._render_labels(key)
            lines.append(f"# TYPE {metric} gauge")
            lines.append(f"{metric}{labels} {value}")
        return "\n".join(lines) + ("\n" if lines else "")

    def _labeled(self, name: str, labels: Dict[str, Any]) -> str:
        if not labels:
            return name
        rendered = ",".join(
            f'{k}="{str(v).replace(chr(34), chr(92)+chr(34))}"'
            for k, v in sorted(labels.items())
        )
        return f"{name}{{{rendered}}}"

    def _render_labels(self, labeled: str) -> str:
        idx = labeled.find("{")
        return labeled[idx:] if idx != -1 else ""

    def _emit(self, kind: str, name: str, value: Any, labels: Dict[str, Any]) -> None:
        logger.debug(
            "metric service=%s kind=%s name=%s value=%s labels=%s",
            self.service_name,
            kind,
            name,
            value,
            labels,
        )
