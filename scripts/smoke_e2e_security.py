"""End-to-end smoke test for the security stack (S2.2 + S2.3).

This script:
  1. Starts vuln-intel on port 4008
  2. Starts dependency-intel on port 4009
  3. Posts a synthetic SBOM to dependency-intel
  4. Correlates with vuln-intel
  5. Computes risk
  6. Reports the result

Usage:
    python scripts/smoke_e2e_security.py
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
from pathlib import Path

import httpx


# Ensure the agent src paths are on the import path so we can import the
# services without installing them.
VULN_INTEL_SRC = os.path.abspath("agents/roles/security/vuln-intel/src")
DEP_INTEL_SRC = os.path.abspath("agents/roles/security/dependency-intel/src")
for p in (VULN_INTEL_SRC, DEP_INTEL_SRC):
    if p not in sys.path:
        sys.path.insert(0, p)

# Use isolated data dirs for the smoke test
os.environ["VULN_INTEL_DATA_DIR"] = str(Path("/tmp/vuln-intel-smoke"))
os.environ["DEP_INTEL_DATA_DIR"] = str(Path("/tmp/dep-intel-smoke"))
os.environ["VULN_INTEL_AUTH_REQUIRED"] = "false"
os.environ["DEP_INTEL_AUTH_REQUIRED"] = "false"
os.environ["VULN_INTEL_PORT"] = "14008"
os.environ["DEP_INTEL_PORT"] = "14009"
os.environ["DEP_INTEL_VULN_INTEL_URL"] = "http://127.0.0.1:14008"


def _pick_free_port() -> int:
    """Return a free localhost port (we hardcode above so this is unused)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _wait_ready(client: httpx.AsyncClient, url: str, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = await client.get(url, timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:  # noqa: BLE001
            await asyncio.sleep(0.2)
    return False


async def main() -> int:
    # Pre-seed vuln-intel with a synthetic record so we can correlate
    # without hitting the real NVD / GHSA / OSV APIs.
    from vuln_intel.api.app import Service as VService
    from vuln_intel.config import get_settings as vget
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

    v_settings = vget()
    v_service = VService(v_settings)
    await v_service.start()

    # Seed three CVEs
    findings: list[CveRecord] = [
        CveRecord(
            id="CVE-2024-99901",
            source=[SourceName.OSV],
            summary="Critical vuln in pypi:foo",
            severity=SeverityAggregate(
                qualitative=SeverityQualitative.CRITICAL,
                cvss_v3=CvssScore(
                    version="3.1", vector="CVSS:3.1/AV:N",
                    score=9.8, severity=SeverityQualitative.CRITICAL,
                    source=ScoreSource.OSV,
                ),
                primary_source=ScoreSource.OSV,
            ),
            affected=[
                AffectedPackage(
                    name="foo", ecosystem="PyPI",
                    purl="pkg:pypi/foo@1.0.0",
                    versions=[AffectedVersionRange(introduced="0", fixed="1.2.4")],
                )
            ],
        ),
        CveRecord(
            id="CVE-2024-99902",
            source=[SourceName.NVD],
            summary="High vuln in npm:bar",
            severity=SeverityAggregate(
                qualitative=SeverityQualitative.HIGH,
                cvss_v3=CvssScore(
                    version="3.1", vector="CVSS:3.1/AV:N",
                    score=7.5, severity=SeverityQualitative.HIGH,
                    source=ScoreSource.NVD_PRIMARY,
                ),
                primary_source=ScoreSource.NVD_PRIMARY,
            ),
            affected=[
                AffectedPackage(
                    name="bar", ecosystem="npm",
                    purl="pkg:npm/bar@2.0.0",
                    versions=[AffectedVersionRange(introduced="0", fixed="2.1.0")],
                )
            ],
        ),
    ]
    for f in findings:
        await v_service.store.upsert(f)

    # Now stand up dependency-intel
    from dependency_intel.api.app import Service as DService
    from dependency_intel.config import get_settings as dget

    d_settings = dget()
    d_service = DService(d_settings)
    await d_service.start()

    print(f"vuln-intel has {len(v_service.store.all())} records")
    print(f"dependency-intel has {len(d_service.store)} graphs")

    # Build a synthetic SBOM with 3 nodes: app -> foo -> bar
    from dependency_intel.models.dto import SbomComponent, SbomDependency, SbomIngestRequest

    req = SbomIngestRequest(
        sbom_id="smoke-sbom",
        components=[
            SbomComponent(purl="pkg:pypi/app@1.0", name="app", is_root=True),
            SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo", is_direct=True),
            SbomComponent(purl="pkg:npm/bar@2.0.0", name="bar"),
        ],
        dependencies=[
            SbomDependency(from_ref="pkg:pypi/app@1.0", to_ref="pkg:pypi/foo@1.0.0"),
            SbomDependency(from_ref="pkg:pypi/foo@1.0.0", to_ref="pkg:npm/bar@2.0.0"),
        ],
    )
    ingest = await d_service.ingest_sbom(req)
    print(f"Ingested SBOM: {ingest.added_nodes} nodes, {ingest.added_edges} edges; graph_id={ingest.graph_id}")

    # In-process correlation: skip the wire and call the matcher
    # directly against vuln-intel's store. This is the same code path
    # that the HTTP /vuln-intel/match endpoint runs.
    from dependency_intel.correlator import build_match_payload, ingest_correlation
    from vuln_intel.matcher import match_components as vi_match
    g = d_service.get_graph(ingest.graph_id)
    payload = build_match_payload(g)

    # Use vuln-intel in-process to avoid spinning up the HTTP server
    # for a smoke test
    records = v_service.store.all()
    raw_findings = vi_match(
        [
            # Re-shape the payload into the MatchRequestComponent shape
            # that vuln-intel.matcher expects
            __import__("vuln_intel").models.dto.MatchRequestComponent(
                purl=p.get("purl"),
                ecosystem=p.get("ecosystem"),
                name=p["name"],
                version=p.get("version"),
                package_manager=p.get("package_manager"),
            )
            for p in payload
        ],
        records,
        min_severity=SeverityQualitative.UNKNOWN,
    )
    print(f"vuln-intel returned {len(raw_findings)} findings")

    # Convert vuln-intel MatchFinding → dependency-intel correlator shape
    norm_findings = [
        {
            "component": {
                "purl": f.component.purl,
                "name": f.component.name,
                "ecosystem": f.component.ecosystem,
                "version": f.component.version,
            },
            "cve": {
                "id": f.cve.id,
                "severity": {"qualitative": f.cve.severity.qualitative.value},
                "epss": {"score": f.cve.epss.score} if f.cve.epss else None,
                "kev": {"exploited": f.cve.kev.exploited} if f.cve.kev else None,
            },
            "confidence": f.confidence,
            "affected": f.affected,
        }
        for f in raw_findings
    ]
    attached, sev = ingest_correlation(g, norm_findings)
    print(f"Attached {attached} findings to graph; severity={sev}")

    # Compute risk
    from dependency_intel.risk import compute_risk
    scores, comp = compute_risk(g, alpha=0.6, damping=0.85)
    print(f"Risk scores: {scores}")
    print(f"Mean risk={comp.mean_risk:.2f}, max risk={comp.max_risk:.2f}")
    print(f"Top priority node: {comp.top_priority[0].name if comp.top_priority else 'none'}")
    for n in comp.top_priority[:3]:
        print(f"  - {n.name} (risk={n.risk_score:.1f}, priority={n.fix_priority}, findings={len(n.findings)})")

    # Validate that the CRITICAL vuln on foo made it into the graph
    assert g.nodes["pkg:pypi/foo@1.0.0"].findings, "foo should have a finding"
    # Validate that risk propagated to the root
    assert scores["pkg:pypi/app@1.0"] > 0, "root should have non-zero propagated risk"
    print("\nE2E SMOKE TEST: PASSED")

    await d_service.stop()
    await v_service.stop()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
