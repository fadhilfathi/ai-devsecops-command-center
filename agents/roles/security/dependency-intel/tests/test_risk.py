"""Tests for the risk propagation algorithm."""
from __future__ import annotations

import pytest

from dependency_intel.builder import build_graph
from dependency_intel.models.dto import SbomComponent, SbomDependency, SbomIngestRequest
from dependency_intel.models.graph import NodeFinding
from dependency_intel.risk import compute_risk, find_vulnerability_clusters


def _build_three_node_graph() -> tuple:
    """app -> foo -> bar."""
    req = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[
            SbomComponent(purl="pkg:pypi/app@1.0", name="app", is_root=True),
            SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo", is_direct=True),
            SbomComponent(purl="pkg:pypi/bar@2.0.0", name="bar"),
        ],
        dependencies=[
            SbomDependency(from_ref="pkg:pypi/app@1.0", to_ref="pkg:pypi/foo@1.0.0"),
            SbomDependency(from_ref="pkg:pypi/foo@1.0.0", to_ref="pkg:pypi/bar@2.0.0"),
        ],
    )
    g, *_ = build_graph(req)
    return g


def test_compute_risk_propagates_to_root() -> None:
    g = _build_three_node_graph()
    g.nodes["pkg:pypi/bar@2.0.0"].findings = [
        NodeFinding(cve_id="CVE-2024-00001", severity="CRITICAL", kev=True),
    ]
    scores, comp = compute_risk(g)
    # Root should pick up risk from the transitive vuln
    assert scores["pkg:pypi/bar@2.0.0"] > 0
    assert scores["pkg:pypi/app@1.0"] > 0
    assert comp.nodes_with_findings == 1


def test_compute_risk_handles_no_findings() -> None:
    g = _build_three_node_graph()
    scores, comp = compute_risk(g)
    # Without findings everyone gets the baseline
    assert all(s >= 0 for s in scores.values())
    assert comp.nodes_with_findings == 0


def test_find_vulnerability_clusters() -> None:
    g = _build_three_node_graph()
    g.nodes["pkg:pypi/bar@2.0.0"].findings = [NodeFinding(cve_id="CVE-X", severity="CRITICAL")]
    g.nodes["pkg:pypi/foo@1.0.0"].findings = [NodeFinding(cve_id="CVE-X", severity="HIGH")]
    clusters = find_vulnerability_clusters(g)
    assert len(clusters) == 1
    assert set(clusters[0].node_ids) == {
        "pkg:pypi/bar@2.0.0",
        "pkg:pypi/foo@1.0.0",
    }
    assert clusters[0].aggregate_severity == "CRITICAL"


def test_compute_risk_uses_alpha() -> None:
    g = _build_three_node_graph()
    g.nodes["pkg:pypi/bar@2.0.0"].findings = [NodeFinding(cve_id="CVE-X", severity="CRITICAL")]
    scores_high, _ = compute_risk(g, alpha=1.0)
    scores_low, _ = compute_risk(g, alpha=0.0)
    # bar (the vulnerable node) is the node where the alpha weight has
    # the biggest effect: with alpha=1.0 the local risk (40) is fully
    # respected, with alpha=0.0 only the baseline (5) is added.
    assert scores_high["pkg:pypi/bar@2.0.0"] > scores_low["pkg:pypi/bar@2.0.0"]
    # The root should also pick up some propagated risk when alpha is high
    assert scores_high["pkg:pypi/app@1.0"] >= scores_low["pkg:pypi/app@1.0"]
