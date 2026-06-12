"""Tests for the dependency graph builder."""
from __future__ import annotations

import pytest

from dependency_intel.builder import build_graph, component_key, merge_graphs
from dependency_intel.models.dto import SbomComponent, SbomDependency, SbomIngestRequest
from dependency_intel.models.graph import EdgeKind, GraphNodeKind


def test_component_key_prefers_purl() -> None:
    c = SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    assert component_key(c) == "pkg:pypi/foo@1.0.0"


def test_component_key_falls_back_to_eco_name() -> None:
    c = SbomComponent(name="foo", version="1.0.0", ecosystem="npm")
    assert component_key(c) == "npm:foo@1.0.0"


def test_component_key_falls_back_to_name() -> None:
    c = SbomComponent(name="foo")
    assert component_key(c) == "foo"


def test_build_graph_adds_nodes_and_edges() -> None:
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
    g, added_n, added_e, skipped = build_graph(req)
    assert added_n == 3
    assert added_e == 2
    assert skipped == 0
    assert "pkg:pypi/app@1.0" in g.root_node_ids
    assert g.nodes["pkg:pypi/foo@1.0.0"].is_direct
    assert g.nodes["pkg:pypi/bar@2.0.0"].direct_dependents == ["pkg:pypi/foo@1.0.0"]


def test_build_graph_dedupes_edges() -> None:
    req = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[SbomComponent(purl="pkg:pypi/app@1.0", name="app", is_root=True),
                    SbomComponent(purl="pkg:pypi/foo@1.0.0", name="foo")],
        dependencies=[
            SbomDependency(from_ref="pkg:pypi/app@1.0", to_ref="pkg:pypi/foo@1.0.0"),
            SbomDependency(from_ref="pkg:pypi/app@1.0", to_ref="pkg:pypi/foo@1.0.0"),
        ],
    )
    g, _, added_e, _ = build_graph(req)
    assert added_e == 1
    assert g.edge_count == 1


def test_build_graph_workspace_merge() -> None:
    r1 = SbomIngestRequest(
        sbom_id="sbom-1",
        components=[SbomComponent(purl="pkg:pypi/a@1", name="a", is_root=True),
                    SbomComponent(purl="pkg:pypi/b@1", name="b")],
        dependencies=[SbomDependency(from_ref="pkg:pypi/a@1", to_ref="pkg:pypi/b@1")],
        workspace=True,
    )
    g1, *_ = build_graph(r1)
    r2 = SbomIngestRequest(
        sbom_id="sbom-2",
        components=[SbomComponent(purl="pkg:pypi/c@1", name="c", is_root=True),
                    SbomComponent(purl="pkg:pypi/b@1", name="b", is_direct=True)],
        dependencies=[SbomDependency(from_ref="pkg:pypi/c@1", to_ref="pkg:pypi/b@1")],
        workspace=True,
    )
    # The builder expects an existing graph in workspace mode, so we pass it explicitly
    g2, *_ = build_graph(r2, existing=g1)
    assert g2.id == g1.id
    assert g2.node_count == 3
    assert g2.nodes["pkg:pypi/b@1"].is_direct is True  # strictest flag wins


def test_merge_graphs_unions() -> None:
    a, *_ = build_graph(SbomIngestRequest(
        sbom_id="a",
        components=[SbomComponent(purl="pkg:npm/x@1", name="x"), SbomComponent(purl="pkg:npm/y@1", name="y")],
        dependencies=[SbomDependency(from_ref="pkg:npm/x@1", to_ref="pkg:npm/y@1")],
    ))
    b, *_ = build_graph(SbomIngestRequest(
        sbom_id="b",
        components=[SbomComponent(purl="pkg:npm/y@1", name="y"), SbomComponent(purl="pkg:npm/z@1", name="z")],
        dependencies=[SbomDependency(from_ref="pkg:npm/y@1", to_ref="pkg:npm/z@1")],
    ))
    merged = merge_graphs([a, b])
    assert merged.node_count == 3
    assert merged.edge_count == 2
    assert "a" in merged.sbom_ids
    assert "b" in merged.sbom_ids
