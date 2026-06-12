"""HTTP-level tests for the vuln-intel FastAPI app."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import respx
from httpx import AsyncClient, Response

from vuln_intel.api.app import create_app
from vuln_intel.config import Settings


@pytest.mark.asyncio
async def test_livez_returns_ok(app_client: AsyncClient) -> None:
    r = await app_client.get("/livez")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_metrics_returns_prometheus(app_client: AsyncClient) -> None:
    r = await app_client.get("/metrics")
    assert r.status_code == 200
    assert "vuln_intel" in r.text


@pytest.mark.asyncio
async def test_get_cve_404(app_client: AsyncClient) -> None:
    r = await app_client.get("/vuln-intel/cve/CVE-9999-9999")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "not_found"


@pytest.mark.asyncio
async def test_lookup_finds_stored(app_client: AsyncClient) -> None:
    # Seed the store via the fixture's own service object
    service: Any = app_client._transport.app.state.service  # type: ignore[attr-defined]
    from vuln_intel.models.cve import CveRecord, SeverityAggregate, SeverityQualitative, SourceName

    await service.store.upsert(
        CveRecord(
            id="CVE-2024-00042",
            source=[SourceName.NVD],
            summary="Stored",
            severity=SeverityAggregate(qualitative=SeverityQualitative.HIGH, primary_source="nvd:primary"),
        )
    )
    r = await app_client.post(
        "/vuln-intel/cve/lookup", json={"ids": ["CVE-2024-00042"]}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["found"][0]["id"] == "CVE-2024-00042"
    assert body["missing"] == []


@pytest.mark.asyncio
async def test_match_endpoint(app_client: AsyncClient) -> None:
    # Seed a vuln and a component
    from vuln_intel.models.cve import (
        AffectedPackage,
        AffectedVersionRange,
        CveRecord,
        CvssScore,
        ScoreSource,
        SeverityAggregate,
        SeverityQualitative,
        SourceName,
    )

    service: Any = app_client._transport.app.state.service  # type: ignore[attr-defined]
    await service.store.upsert(
        CveRecord(
            id="CVE-2024-00050",
            source=[SourceName.OSV],
            summary="x",
            severity=SeverityAggregate(
                qualitative=SeverityQualitative.HIGH,
                cvss_v3=CvssScore(version="3.1", vector="CVSS:3.1/AV:N", score=7.5, severity=SeverityQualitative.HIGH, source=ScoreSource.OSV),
                primary_source=ScoreSource.OSV,
            ),
            affected=[AffectedPackage(name="foo", ecosystem="PyPI", purl="pkg:pypi/foo@1.0.0",
                                       versions=[AffectedVersionRange(introduced_in="0", fixed="1.2.4")])],
        )
    )
    r = await app_client.post(
        "/vuln-intel/match",
        json={
            "components": [{"purl": "pkg:pypi/foo@1.0.0", "name": "foo", "version": "1.0.0"}],
            "min_severity": "UNKNOWN",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_components"] == 1
    assert body["affected_components"] == 1
    assert len(body["findings"]) == 1


@pytest.mark.asyncio
async def test_stats_endpoint(app_client: AsyncClient) -> None:
    r = await app_client.get("/vuln-intel/stats")
    assert r.status_code == 200
    body = r.json()
    assert "total_records" in body
    assert "by_source" in body
    assert "severity_distribution" in body
