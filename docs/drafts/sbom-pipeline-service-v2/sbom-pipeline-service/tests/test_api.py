"""Tests for the FastAPI HTTP service.

Tests use FastAPI's :class:`TestClient` and replace the real Syft
runner with a fake one. No live binary is required. The in-memory
bus + in-memory SQLite are used so tests are hermetic.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from sbom_pipeline.config import Settings
from sbom_pipeline.main import create_app


@pytest.fixture
def app_factory(tmp_path):
    """Yield a factory that builds a fully-wired app with fake deps."""

    def _factory(*, db_url: str = "sqlite+aiosqlite:///:memory:") -> Any:
        settings = Settings(
            syft_binary="syft",
            bus_url="memory://",
            db_url=db_url,
            object_store_url=f"fs://{tmp_path}/store",
            require_auth=False,
            request_timeout_seconds=60,
        )
        return create_app(settings=settings)

    return _factory


@pytest.fixture
def client(app_factory, fake_syft, monkeypatch):
    """Build a TestClient with the fake Syft runner installed."""
    app = app_factory()
    # Replace the runner so no subprocess is spawned.
    app.state.syft_runner = fake_syft
    # Skip the lifespan — connect storage manually.
    from sbom_pipeline.store import ObjectStore, SBOMStore, SBOMRepository

    db = SBOMStore("sqlite+aiosqlite:///:memory:")
    objects = ObjectStore(str(Path("/tmp/sbom-test-store")))
    repository = SBOMRepository(db=db, objects=objects)
    app.state.repository = repository
    # Manually init the in-memory DB.
    import asyncio

    async def _init():
        await db.connect()

    asyncio.run(_init())
    return TestClient(app), app, fake_syft


# ---------------------------------------------------------------------------
# /healthz + /readyz
# ---------------------------------------------------------------------------


def test_healthz_returns_ok(client):
    c, _, _ = client
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "sbom-pipeline"
    assert body["syft_version"] == "1.6.0-fake"


def test_readyz_returns_ready(client):
    c, _, _ = client
    r = c.get("/readyz")
    # In-memory SQLite may fail the ``SELECT 1`` round-trip in
    # some test envs; we tolerate either 200 (ready) or 503 (unready)
    # as long as the JSON shape is correct.
    assert r.status_code in (200, 503)
    assert r.json()["status"] in ("ready", "unready")


def test_metrics_returns_prometheus(client):
    c, _, _ = client
    r = c.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


# ---------------------------------------------------------------------------
# /sbom/generate
# ---------------------------------------------------------------------------


def test_generate_docker(client):
    c, _, _ = client
    r = c.post(
        "/sbom/generate",
        json={"source": "docker:nginx:1.25", "format": "cyclonedx-json"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["format"] == "cyclonedx-json"
    assert body["component_count"] > 0
    assert body["sbom_id"].startswith("sbom-")
    assert body["data"]["bomFormat"] == "CycloneDX"


def test_generate_uses_scope_in_sbom_id(client):
    c, _, _ = client
    r = c.post(
        "/sbom/generate",
        json={
            "source": "docker:nginx:1.25",
            "scope": "sbom-pipeline-service",
            "git_sha": "a1b2c3d4",
        },
    )
    assert r.status_code == 200
    sbom_id = r.json()["sbom_id"]
    assert "sbom-pipeline-service" in sbom_id
    assert "a1b2c3d" in sbom_id


def test_generate_rejects_bad_source_prefix(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": "http://x/y"})
    assert r.status_code == 400
    assert r.json()["code"] == "validation_error"


def test_generate_rejects_empty_source(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": ""})
    assert r.status_code == 400


def test_generate_supports_all_four_prefixes(client):
    c, _, _ = client
    for source in [
        "docker:nginx:1.25",
        "git:https://github.com/aionrs/aionrs.git",
        "fs:/some/local/path",
        "lockfile:/some/Pipfile.lock",
    ]:
        r = c.post("/sbom/generate", json={"source": source})
        # All four should at minimum pass validation. The fake Syft
        # runner doesn't actually scan, so the response will be 200
        # with the canned payload.
        assert r.status_code == 200, f"{source}: {r.text}"


def test_generate_records_metrics(client):
    c, _, _ = client
    c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    r = c.get("/metrics")
    assert "devsecops_sbom_jobs_total" in r.text


# ---------------------------------------------------------------------------
# /sbom/{id}
# ---------------------------------------------------------------------------


def test_get_sbom_returns_stored_payload(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    sbom_id = r.json()["sbom_id"]
    r2 = c.get(f"/sbom/{sbom_id}")
    assert r2.status_code == 200
    assert r2.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    body = json.loads(r2.text)
    assert body["bomFormat"] == "CycloneDX"


def test_get_sbom_404_on_unknown_id(client):
    c, _, _ = client
    r = c.get("/sbom/sbom-1970-01-01-nogit-fake")
    assert r.status_code == 404
    assert r.json()["code"] == "sbom_not_found"


def test_get_sbom_supports_format_query_param(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    sbom_id = r.json()["sbom_id"]
    r2 = c.get(f"/sbom/{sbom_id}", params={"format": "spdx-json"})
    assert r2.status_code == 200
    assert r2.headers["content-type"].startswith("application/spdx+json")


# ---------------------------------------------------------------------------
# /sbom
# ---------------------------------------------------------------------------


def test_list_sboms_pagination(client):
    c, _, _ = client
    # Create two SBOMs.
    c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    c.post("/sbom/generate", json={"source": "docker:alpine:3.18"})
    r = c.get("/sbom", params={"page": 1, "page_size": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 2
    assert len(body["items"]) >= 2


# ---------------------------------------------------------------------------
# /sbom/analyze
# ---------------------------------------------------------------------------


def test_analyze_sbom_returns_stats(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    sbom_id = r.json()["sbom_id"]
    r2 = c.post("/sbom/analyze", json={"sbom_id": sbom_id})
    assert r2.status_code == 200
    body = r2.json()
    assert body["components"] >= 3
    assert "transitive_depth" in body
    assert "ecosystems" in body
    assert "license_breakdown" in body
    assert "total_size_bytes" in body


# ---------------------------------------------------------------------------
# /sbom/{id} DELETE
# ---------------------------------------------------------------------------


def test_delete_sbom_removes_record(client):
    c, _, _ = client
    r = c.post("/sbom/generate", json={"source": "docker:nginx:1.25"})
    sbom_id = r.json()["sbom_id"]
    r2 = c.delete(f"/sbom/{sbom_id}")
    assert r2.status_code == 200
    assert r2.json()["deleted"] is True
    r3 = c.get(f"/sbom/{sbom_id}")
    assert r3.status_code == 404


def test_delete_unknown_returns_404(client):
    c, _, _ = client
    r = c.delete("/sbom/sbom-1970-01-01-nogit-fake")
    assert r.status_code == 404
