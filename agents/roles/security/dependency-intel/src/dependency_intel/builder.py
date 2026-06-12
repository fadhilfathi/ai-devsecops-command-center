"""Build a :class:`DependencyGraph` from an SBOM ingest request.

The builder is deliberately tolerant of input:

* ``purl`` is the canonical key; when missing we fall back to
  ``ecosystem:name@version`` and finally to ``bom-ref`` (CycloneDX).
* A component may be declared as both direct and transitive in
  different SBOMs — we keep the strictest (i.e. direct) flag.
* Edges are deduped on (from, to, kind, scope).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Iterable

from .models.dto import SbomComponent, SbomDependency, SbomIngestRequest
from .models.graph import DependencyGraph, EdgeKind, GraphEdge, GraphNode, GraphNodeKind

logger = logging.getLogger(__name__)


def _coerce_edge_kind(raw: str | None) -> EdgeKind:
    if not raw:
        return EdgeKind.UNKNOWN
    s = raw.strip().lower()
    mapping = {
        "runtime": EdgeKind.RUNTIME,
        "required": EdgeKind.RUNTIME,
        "dependencies": EdgeKind.RUNTIME,
        "dev": EdgeKind.DEVELOPMENT,
        "development": EdgeKind.DEVELOPMENT,
        "optional": EdgeKind.OPTIONAL,
        "build": EdgeKind.BUILD,
        "test": EdgeKind.TEST,
    }
    return mapping.get(s, EdgeKind.UNKNOWN)


def _coerce_node_kind(raw: str | None) -> GraphNodeKind:
    if not raw:
        return GraphNodeKind.LIBRARY
    s = raw.strip().lower()
    mapping = {
        "application": GraphNodeKind.APPLICATION,
        "library": GraphNodeKind.LIBRARY,
        "framework": GraphNodeKind.FRAMEWORK,
        "operating-system": GraphNodeKind.OPERATING_SYSTEM,
        "device": GraphNodeKind.DEVICE,
        "container": GraphNodeKind.CONTAINER,
        "file": GraphNodeKind.FILE,
    }
    return mapping.get(s, GraphNodeKind.UNKNOWN)


def component_key(comp: SbomComponent) -> str:
    """Compute a stable node id for a component.

    Order of preference:
      1. ``purl``
      2. ``ecosystem:name@version``
      3. ``name@version``
      4. ``name``  (last resort — version is unknown)
    """
    if comp.purl:
        return comp.purl.strip().lower()
    eco = (comp.ecosystem or "").strip().lower()
    name = (comp.name or "").strip().lower()
    version = (comp.version or "").strip().lower()
    if eco and name:
        return f"{eco}:{name}@{version}" if version else f"{eco}:{name}"
    if name:
        return f"{name}@{version}" if version else name
    return hashlib.sha1(repr(comp).encode("utf-8")).hexdigest()[:16]


def build_graph(
    request: SbomIngestRequest,
    *,
    existing: DependencyGraph | None = None,
    max_nodes: int = 50_000,
    max_edges: int = 500_000,
) -> tuple[DependencyGraph, int, int, int]:
    """Return ``(graph, added_nodes, added_edges, skipped_nodes)``.

    If ``existing`` is provided and ``request.workspace`` is True, the
    new SBOM is merged into the existing graph; otherwise a new graph
    is created.
    """
    if existing is not None and request.workspace:
        graph = existing
    else:
        graph = DependencyGraph(
            name=request.name or request.sbom_id,
            sbom_ids=[request.sbom_id] if existing is None else list(existing.sbom_ids) + [request.sbom_id],
        )
    if request.sbom_id not in graph.sbom_ids:
        graph.sbom_ids.append(request.sbom_id)

    # --- nodes -------------------------------------------------------------
    added_nodes = 0
    skipped_nodes = 0
    for comp in request.components:
        if graph.node_count + added_nodes >= max_nodes:
            skipped_nodes += 1
            logger.warning("graph_node_limit_reached limit=%s skipped=%s", max_nodes, skipped_nodes)
            continue
        key = component_key(comp)
        if key in graph.nodes:
            node = graph.nodes[key]
            # Merge flags (strictest wins)
            node.is_direct = node.is_direct or comp.is_direct
            node.is_root = node.is_root or comp.is_root
            if request.sbom_id not in node.sbom_ids:
                node.sbom_ids.append(request.sbom_id)
            if comp.purl and not node.purl:
                node.purl = comp.purl
            if comp.version and not node.version:
                node.version = comp.version
            if comp.ecosystem and not node.ecosystem:
                node.ecosystem = comp.ecosystem
            if comp.kind:
                node.kind = _coerce_node_kind(comp.kind)
            node.properties.update(comp.properties or {})
        else:
            node = GraphNode(
                id=key,
                purl=comp.purl,
                ecosystem=comp.ecosystem,
                name=comp.name,
                version=comp.version,
                kind=_coerce_node_kind(comp.kind),
                is_direct=comp.is_direct,
                is_root=comp.is_root,
                sbom_ids=[request.sbom_id],
                properties=comp.properties or {},
            )
            graph.nodes[key] = node
            added_nodes += 1
        if comp.is_root and key not in graph.root_node_ids:
            graph.root_node_ids.append(key)

    # --- edges -------------------------------------------------------------
    added_edges = 0
    seen_edges: set[tuple[str, str, EdgeKind, str | None]] = {
        (e.from_node, e.to_node, e.kind, e.scope) for e in graph.edges
    }
    for dep in request.dependencies:
        if graph.edge_count + added_edges >= max_edges:
            logger.warning("graph_edge_limit_reached limit=%s", max_edges)
            break
        # Auto-create missing endpoint nodes
        for ref in (dep.from_ref, dep.to_ref):
            ref_key = _ref_key(ref, graph)
            if ref_key not in graph.nodes:
                # add a stub node so the edge resolves
                graph.nodes[ref_key] = GraphNode(
                    id=ref_key,
                    name=ref_key.split("@")[0].split(":")[-1] or ref_key,
                )
                added_nodes += 1
        kind = _coerce_edge_kind(dep.kind)
        from_k = _ref_key(dep.from_ref, graph)
        to_k = _ref_key(dep.to_ref, graph)
        sig = (from_k, to_k, kind, dep.scope)
        if sig in seen_edges:
            continue
        seen_edges.add(sig)
        graph.edges.append(
            GraphEdge(
                **{"from": from_k, "to": to_k},
                kind=kind,
                scope=dep.scope,
            )
        )
        added_edges += 1
        # Update the dependent list of the dependency
        if from_k in graph.nodes and to_k in graph.nodes:
            if from_k not in graph.nodes[to_k].direct_dependents:
                graph.nodes[to_k].direct_dependents.append(from_k)

    return graph, added_nodes, added_edges, skipped_nodes


def _ref_key(ref: str, graph: DependencyGraph) -> str:
    """Resolve a ``bom-ref`` or ``purl`` to a node id."""
    if ref in graph.nodes:
        return ref
    # Try lowercase purl
    if ref.lower() in graph.nodes:
        return ref.lower()
    # Try to find a node whose name matches
    for nid, node in graph.nodes.items():
        if node.purl == ref:
            return nid
    return ref


def merge_graphs(graphs: Iterable[DependencyGraph]) -> DependencyGraph:
    """Merge a collection of graphs into a single workspace graph.

    Nodes are deduplicated by id; edges are unioned; the resulting
    graph's sbom_ids is the union of the inputs.
    """
    out = DependencyGraph()
    for g in graphs:
        for nid, node in g.nodes.items():
            if nid in out.nodes:
                existing = out.nodes[nid]
                existing.is_direct = existing.is_direct or node.is_direct
                existing.is_root = existing.is_root or node.is_root
                for sbom_id in node.sbom_ids:
                    if sbom_id not in existing.sbom_ids:
                        existing.sbom_ids.append(sbom_id)
            else:
                out.nodes[nid] = node.model_copy(deep=True)
        for e in g.edges:
            sig = (e.from_node, e.to_node, e.kind, e.scope)
            if not any(
                (ee.from_node, ee.to_node, ee.kind, ee.scope) == sig for ee in out.edges
            ):
                out.edges.append(e)
        for sbom_id in g.sbom_ids:
            if sbom_id not in out.sbom_ids:
                out.sbom_ids.append(sbom_id)
        for rid in g.root_node_ids:
            if rid not in out.root_node_ids:
                out.root_node_ids.append(rid)
    return out
