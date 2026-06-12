"""Tests for the telemetry buffer + Prometheus rendering."""

from __future__ import annotations

import pytest

from sbom_generator.telemetry import Telemetry


def test_inc_and_observe_and_gauge():
    t = Telemetry(service_name="test")
    t.inc("jobs")
    t.inc("jobs", value=2)
    t.observe("duration", 10.0)
    t.observe("duration", 20.0)
    t.gauge("active", 3)
    assert t.counters["jobs"] == 3
    assert t.histograms["duration"] == [10.0, 20.0]
    assert t.gauges["active"] == 3


def test_labels_applied_to_counter():
    t = Telemetry(service_name="test")
    t.inc("jobs", format="cyclonedx-json")
    t.inc("jobs", format="spdx-json")
    assert t.counters['jobs{format="cyclonedx-json"}'] == 1
    assert t.counters['jobs{format="spdx-json"}'] == 1


def test_render_prometheus_includes_counters():
    t = Telemetry(service_name="test")
    t.inc("requests_total")
    body = t.render_prometheus()
    assert "# TYPE requests_total counter" in body
    assert "requests_total 1" in body


def test_render_prometheus_handles_empty():
    t = Telemetry(service_name="test")
    assert t.render_prometheus() == ""


def test_span_records_duration():
    t = Telemetry(service_name="test")
    with t.span("op"):
        pass
    assert any("op.duration_ms" in k for k in t.histograms)


def test_span_propagates_exceptions():
    t = Telemetry(service_name="test")
    with pytest.raises(RuntimeError):
        with t.span("op"):
            raise RuntimeError("boom")
    assert any(e["event"].endswith(".error") for e in t.events)
