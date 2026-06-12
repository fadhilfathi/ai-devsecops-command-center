"""HTTP-level tests for the dependency-intel FastAPI app."""
from __future__ import annotations

import pytest
import respx
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_livez_ok(app_client: AsyncClient) -> None:
    r = await app_client.get("/livez")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_metrics_endpoint(app_client: AsyncClient) -> None:
    r = await app_client.get("/metrics")
    assert r.status_code == 200
    assert "dep_intel" in r.text


@pytest.mark.asyncio
async def test_build_then_summary(app_client: AsyncClient) -> None:
    payload = {
        "sbom_id": "sbom-1",
        "components": [
            {"purl": "pkg:pypi/app@1.0", "name": "app", "is_root": True},
            {"purl": "pkg:pypi/foo@1.0.0", "name": "foo", "is_direct": True},
            {"purl": "pkg:pypi/bar@2.0.0", "name": "bar"},
        ],
        "dependencies": [
            {"from_ref": "pkg:pypi/app@1.0", "to_ref": "pkg:pypi/foo@1.0.0"},
            {"from_ref": "pkg:pypi/foo@1.0.0", "to_ref": "pkg:pypi/bar@2.0.0"},
        ],
    }
    r = await app_client.post("/dep-intel/graph/build", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_nodes"] == 3
    assert body["total_edges"] == 2
    graph_id = body["graph_id"]

    r2 = await app_client.get(f"/dep-intel/graph/{graph_id}")
    assert r2.status_code == 200
    summary = r2.json()
    assert summary["node_count"] == 3
    assert summary["edge_count"] == 2


@pytest.mark.asyncio
async def test_correlate_then_risk(app_client: AsyncClient) -> None:
    # 1) build a tiny graph
    r = await app_client.post(
        "/dep-intel/graph/build",
        json={
            "sbom_id": "sbom-1",
            "components": [
                {"purl": "pkg:pypi/app@1.0", "name": "app", "is_root": True},
                {"purl": "pkg:pypi/foo@1.0.0", "name": "foo", "is_direct": True},
            ],
            "dependencies": [
                {"from_ref": "pkg:pypi/app@1.0", "to_ref": "pkg:pypi/foo@1.0.0"},
            ],
        },
    )
    assert r.status_code == 200, r.text
    graph_id = r.json()["graph_id"]

    # 2) Mock vuln-intel and correlate
    base = app_client._transport.app.state.service.settings.vuln_intel_url  # type: ignore[attr-defined]
    with respx.mock(base_url=base) as mock:
        mock.post("/vuln-intel/match").respond(
            200,
            json={
                "findings": [
                    {
                        "component": {"purl": "pkg:pypi/foo@1.0.0"},
                        "cve": {
                            "id": "CVE-2024-00001",
                            "severity": {"qualitative": "CRITICAL"},
                            "epss": {"score": 0.9},
                            "kev": {"exploited": True},
                        },
                        "confidence": 0.95,
                        "affected": True,
                    }
                ],
                "total_components": 1,
                "affected_components": 1,
                "severity_counts": {"CRITICAL": 1},
            },
        )
        r2 = await app_client.post(
            f"/dep-intel/graph/{graph_id}/correlate",
            json={"refresh_from_vuln_intel": True},
        )
        assert r2.status_code == 200, r2.text
        body = r2.json()
        assert body["findings_attached"] == 1

    # 3) Compute risk
    r3 = await app_client.post(
        "/dep-intel/risk/calculate", params={"graph_id": graph_id}, json={}
    )
    assert r3.status_code == 200, r3.text
    body = r3.json()
    assert "pkg:pypi/foo@1.0.0" in body["risk_scores"]
    assert body["risk_scores"]["pkg:pypi/foo@1.0.0"] > 0


@pytest.mark.asyncio
async def test_export_json(app_client: AsyncClient) -> None:
    r = await app_client.post(
        "/dep-intel/graph/build",
        json={
            "sbom_id": "sbom-1",
            "components": [{"purl": "pkg:pypi/app@1.0", "name": "app", "is_root": True}],
        },
    )
    assert r.status_code == 200, r.text
    graph_id = r.json()["graph_id"]
    r2 = await app_client.get(f"/dep-intel/graph/{graph_id}/export?fmt=json")
    assert r2.status_code == 200
    assert r2.headers["content-type"].startswith("application/json")


@pytest.mark.asyncio
async def test_export_graphml(app_client: AsyncClient) -> None:
    r = await app_client.post(
        "/dep-intel/graph/build",
        json={
            "sbom_id": "sbom-1",
            "components": [{"purl": "pkg:pypi/app@1.0", "name": "app", "is_root": True}],
        },
    )
    graph_id = r.json()["graph_id"]
    r2 = await app_client.get(f"/dep-intel/graph/{graph_id}/export?fmt=graphml")
    assert r2.status_code == 200
    assert "graphml" in r2.text


@pytest.mark.asyncio
async def test_export_dot(app_client: AsyncClient) -> None:
    r = await app_client.post(
        "/dep-intel/graph/build",
        json={
            "sbom_id": "sbom-1",
            "components": [{"purl": "pkg:pypi/app@1.0", "name": "app", "is_root": True}],
        },
    )
    graph_id = r.json()["graph_id"]
    r2 = await app_client.get(f"/dep-intel/graph/{graph_id}/export?fmt=dot")
    assert r2.status_code == 200
    assert "digraph" in r2.text
