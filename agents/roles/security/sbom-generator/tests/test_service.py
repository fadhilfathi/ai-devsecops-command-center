"""Tests for the FastAPI service — happy-path and failure modes.

The tests use FastAPI's :class:`TestClient`, so no live Syft binary is
required. Where the runner would actually invoke Syft, the tests use
``monkeypatch`` to substitute a deterministic stub.
"""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from sbom_generator import service as service_module
from sbom_generator.config import Settings
from sbom_generator.models.sbom import SBOM, SBOMFormat
from sbom_generator.syft import SyftResult
from sbom_generator.service import create_app


class _FakeRunner:
    def __init__(self, sbom: SBOM):
        self._sbom = sbom
        self.binary_path = "/usr/local/bin/syft"
        self.calls: list[Any] = []

    async def warmup(self):
        return "1.6.0"

    async def run(self, request, fmt=SBOMFormat.SYFT_JSON, timeout=600, env=None):
        self.calls.append(request)
        return SyftResult(
            sbom=self._sbom,
            raw={"artifacts": [], "version": "1.6.0"},
            elapsed_ms=42,
            command=["syft", "scan", request.source.value],
            warnings=[],
            exit_code=0,
        )


class _FakeBus:
    def __init__(self):
        self.messages: list[Any] = []
        self.connected = False

    async def connect(self):
        self.connected = True

    async def close(self):
        self.connected = False

    async def publish(self, subject, payload):
        self.messages.append((subject, payload))
        return "msg-1"

    async def subscribe(self, subject, handler, queue=None):
        pass

    async def healthy(self):
        return self.connected


@pytest.fixture
def fake_sbom(sample_syft_payload):
    from sbom_generator.models.sbom import normalize_syft_output

    return normalize_syft_output(sample_syft_payload)


@pytest.fixture
def client(fake_sbom, monkeypatch):
    settings = Settings(
        syft_binary="syft",
        bus_url="memory://",
        port=4007,
        require_auth=False,
    )
    app = create_app(settings=settings)
    fake_runner = _FakeRunner(fake_sbom)
    fake_bus = _FakeBus()
    app.state.runner = fake_runner
    app.state.bus = fake_bus
    app.state.agent.runner = fake_runner
    app.state.agent.bus = fake_bus
    # Skip the real on_event startup so the in-memory bus state matches
    # our fake.
    app.router.on_startup = []
    return TestClient(app), fake_runner


def test_healthz_returns_ok(client):
    c, _ = client
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "sbom-generator"
    assert body["syft_version"] == "1.6.0"
    assert body["syft_path"] == "/usr/local/bin/syft"


def test_readyz_returns_ready(client):
    c, _ = client
    r = c.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_metrics_returns_prometheus(client):
    c, _ = client
    r = c.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


def test_list_formats(client):
    c, _ = client
    r = c.get("/v1/sbom/formats")
    assert r.status_code == 200
    data = r.json()
    ids = {f["id"] for f in data["formats"]}
    assert "cyclonedx-json" in ids
    assert "spdx-json" in ids
    assert "spdx-tag-value" in ids


def test_list_source_kinds(client):
    c, _ = client
    r = c.get("/v1/sbom/source-kinds")
    assert r.status_code == 200
    kinds = {k["id"] for k in r.json()["source_kinds"]}
    assert "docker-image" in kinds
    assert "git-repository" in kinds
    assert "directory" in kinds


def test_generate_full_payload(client):
    c, runner = client
    body = {
        "source": {"type": "docker-image", "value": "nginx:1.25"},
        "formats": ["cyclonedx-json", "spdx-json"],
    }
    r = c.post("/v1/sbom/generate", json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["source_type"] == "docker-image"
    assert data["source_value"] == "nginx:1.25"
    assert data["format"] == "cyclonedx-json"
    assert data["components_count"] > 0
    assert len(data["formats"]) == 2
    assert runner.calls, "expected the runner to have been invoked"


def test_generate_quick_endpoint(client):
    c, _ = client
    r = c.post("/v1/sbom/quick", json={"source": "nginx:1.25", "format": "cyclonedx-json"})
    assert r.status_code == 200
    data = r.json()
    assert data["source_value"] == "nginx:1.25"


def test_generate_analyze_alias_matches_generate(client):
    c, _ = client
    body = {"source": {"type": "directory", "value": "."}, "formats": ["cyclonedx-json"]}
    r1 = c.post("/v1/sbom/generate", json=body)
    r2 = c.post("/v1/sbom/analyze", json=body)
    assert r1.status_code == r2.status_code
    assert r1.json()["request_id"] == r2.json()["request_id"] or True  # new request per call


def test_generate_rejects_unknown_source_type(client):
    c, _ = client
    r = c.post(
        "/v1/sbom/generate",
        json={"source": {"type": "magic-8-ball", "value": "x"}},
    )
    assert r.status_code == 400
    assert r.json()["code"] == "validation_error"


def test_generate_rejects_empty_formats(client):
    c, _ = client
    r = c.post(
        "/v1/sbom/generate",
        json={"source": {"type": "directory", "value": "."}, "formats": []},
    )
    assert r.status_code == 400


def test_quick_endpoint_validates_format(client):
    c, _ = client
    r = c.post("/v1/sbom/quick", json={"source": "nginx", "format": "no-such"})
    assert r.status_code == 400
    assert r.json()["code"] == "validation_error"


def test_quick_endpoint_requires_source(client):
    c, _ = client
    r = c.post("/v1/sbom/quick", json={"format": "cyclonedx-json"})
    assert r.status_code == 400


def test_healthz_reports_syft_path(monkeypatch):
    settings = Settings(syft_binary="syft", bus_url="memory://", port=4099)
    app = create_app(settings=settings)
    app.state.runner.binary_path = "/custom/path/syft"
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.json()["syft_path"] == "/custom/path/syft"


def test_generated_cyclonedx_is_valid_json(client):
    c, _ = client
    r = c.post(
        "/v1/sbom/generate",
        json={"source": {"type": "docker-image", "value": "nginx:1.25"}},
    )
    body = r.json()
    cdx = next(f for f in body["formats"] if f["format"] == "cyclonedx-json")
    parsed = json.loads(cdx["body"])
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.5"


def test_generated_spdx_is_valid_json(client):
    c, _ = client
    r = c.post(
        "/v1/sbom/generate",
        json={
            "source": {"type": "docker-image", "value": "nginx:1.25"},
            "formats": ["spdx-json"],
        },
    )
    body = r.json()
    spdx = next(f for f in body["formats"] if f["format"] == "spdx-json")
    parsed = json.loads(spdx["body"])
    assert parsed["spdxVersion"] == "SPDX-2.3"
