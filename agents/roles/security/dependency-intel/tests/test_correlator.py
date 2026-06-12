"""Tests for the upstream correlation client."""
from __future__ import annotations

from typing import Any

import pytest
import respx
from httpx import AsyncClient

from dependency_intel.builder import build_graph
from dependency_intel.config import Settings
from dependency_intel.correlator import VulnIntelClient, build_match_payload, ingest_correlation
from dependency_intel.models.dto import SbomComponent, SbomDependency, SbomIngestRequest
from dependency_intel.models.graph import NodeFinding


@pytest.mark.asyncio
async def test_health_succeeds(settings: Settings) -> None:
    client = VulnIntelClient(settings)
    try:
        with respx.mock(base_url=settings.vuln_intel_url) as mock:
            mock.get("/livez").respond(200, json={"status": "ok"})
            assert await client.health() is True
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_health_fails_on_5xx(settings: Settings) -> None:
    client = VulnIntelClient(settings)
    try:
        with respx.mock(base_url=settings.vuln_intel_url) as mock:
            mock.get("/livez").respond(503, json={})
            assert await client.health() is False
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_match_components(settings: Settings) -> None:
    client = VulnIntelClient(settings)
    try:
        with respx.mock(base_url=settings.vuln_intel_url) as mock:
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
            findings = await client.match_components([{"purl": "pkg:pypi/foo@1.0.0", "name": "foo"}])
            assert len(findings) == 1
            assert findings[0]["cve"]["id"] == "CVE-2024-00001"
    finally:
        await client.aclose()


def test_ingest_correlation_attaches_findings() -> None:
    req = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[
            SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo", is_direct=True),
            SbomComponent(purl="pkg:pypi/bar@1.0.0", name="bar", is_direct=True),
        ],
    )
    g, *_ = build_graph(req)
    findings = [
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
    ]
    attached, sev = ingest_correlation(g, findings)
    assert attached == 1
    assert sev["CRITICAL"] == 1
    assert g.nodes["pkg:pypi/foo@1.0.0"].findings[0].cve_id == "CVE-2024-00001"


def test_ingest_correlation_no_duplicate() -> None:
    req = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo")],
    )
    g, *_ = build_graph(req)
    finding = {
        "component": {"purl": "pkg:pypi/foo@1.0.0"},
        "cve": {"id": "CVE-X", "severity": {"qualitative": "HIGH"}},
        "confidence": 0.9,
        "affected": True,
    }
    ingest_correlation(g, [finding])
    ingest_correlation(g, [finding])  # duplicate
    assert len(g.nodes["pkg:pypi/foo@1.0.0"].findings) == 1


def test_build_match_payload() -> None:
    req = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0", ecosystem="PyPI")],
    )
    g, *_ = build_graph(req)
    payload = build_match_payload(g)
    assert payload[0]["purl"] == "pkg:pypi/foo@1.0.0"
    assert payload[0]["name"] == "foo"
    assert payload[0]["version"] == "1.0.0"
    assert payload[0]["ecosystem"] == "PyPI"
