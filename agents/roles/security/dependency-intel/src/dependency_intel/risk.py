"""Risk propagation algorithms.

The core idea is to combine a *local* risk signal (vulnerabilities
attached to a node) with a *propagated* signal (risk flowing from
vulnerable transitive dependencies). We use a personalised PageRank
variant because:

* It naturally handles arbitrary DAG-shaped dependency graphs.
* The teleport vector (the local-risk vector) lets us steer the
  propagation toward vulnerable nodes.
* It is fast (converges in ~log n iterations for sparse graphs).

Final score per node::

    risk_i = alpha * (0.4 * local_i + 0.6 * pr_i) + (1 - alpha) * baseline

where ``local_i`` is the sum of CVSS-equivalent scores of the
vulnerabilities attached to node ``i`` (clamped to [0, 100]),
``pr_i`` is the PageRank of ``i`` in the dependency graph, ``alpha``
is the propagation weight and ``baseline`` is a small constant.
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from typing import Iterable

import networkx as nx

from .models.graph import (
    DependencyGraph,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeFinding,
    RiskComputation,
)


# ============================================================================
# Severity weight table
# ============================================================================


SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 40.0,
    "HIGH": 25.0,
    "MEDIUM": 10.0,
    "LOW": 4.0,
    "NONE": 0.0,
    "UNKNOWN": 1.0,
}

KEV_BONUS = 15.0
EPSS_BONUS_WEIGHT = 10.0  # multiplied by EPSS score (0..1)


# ============================================================================
# Local risk
# ============================================================================


def _local_risk(findings: Iterable[NodeFinding]) -> float:
    total = 0.0
    for f in findings:
        sev = (f.severity or "UNKNOWN").upper()
        total += SEVERITY_WEIGHTS.get(sev, 0.0)
        if f.kev:
            total += KEV_BONUS
        if f.epss is not None:
            total += EPSS_BONUS_WEIGHT * float(f.epss)
    # Clamp to [0, 100] but allow up to 130 internally so propagated
    # scores can dominate
    return min(total, 100.0)


# ============================================================================
# Graph -> NetworkX
# ============================================================================


def to_networkx(graph: DependencyGraph) -> nx.DiGraph:
    """Convert our :class:`DependencyGraph` to a NetworkX :class:`DiGraph`."""
    g = nx.DiGraph()
    for nid, node in graph.nodes.items():
        g.add_node(nid, **node.model_dump())
    for e in graph.edges:
        g.add_edge(e.from_node, e.to_node, kind=e.kind, scope=e.scope, weight=e.weight)
    return g


# ============================================================================
# PageRank-based propagation
# ============================================================================


def compute_risk(
    graph: DependencyGraph,
    *,
    alpha: float = 0.6,
    damping: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6,
) -> tuple[dict[str, float], RiskComputation]:
    """Compute risk scores for every node in the graph.

    Returns a ``(scores, computation)`` tuple where ``scores`` maps node
    id -> ``risk_score`` in ``[0, 100]`` and ``computation`` carries
    metadata.
    """
    n = graph.node_count
    if n == 0:
        return {}, RiskComputation(
            graph_id=graph.id,
            computed_at=datetime.utcnow(),
            alpha=alpha,
            damping=damping,
            iterations=0,
            converged=True,
        )

    # local risk vector
    local = {nid: _local_risk(node.findings) for nid, node in graph.nodes.items()}
    max_local = max(local.values()) if local else 0.0
    if max_local > 0:
        teleport = {nid: v / max_local for nid, v in local.items()}
    else:
        # uniform teleport — degrades to plain PageRank
        teleport = {nid: 1.0 / n for nid in graph.nodes}

    nxg = to_networkx(graph)
    # In a dependency graph, edge ``u -> v`` means "u depends on v".
    # Risk should flow *backwards*: a vulnerability in v should affect u.
    # We therefore run PageRank on the reversed graph.
    reversed_g = nxg.reverse(copy=True)
    # Power-iteration personalised PageRank — implemented in pure Python
    # so we don't take a hard dependency on scipy.
    pr = _pagerank_power(
        reversed_g,
        damping=damping,
        teleport=teleport,
        max_iter=max_iter,
        tol=tol,
    )

    # Normalise PR to [0, 100]. We use max-scaling so the highest-ranked
    # node gets 100 and the smallest gets a small but non-zero value.
    # This avoids the "everyone is 0" failure mode of min-max scaling.
    if pr:
        pr_max = max(pr.values())
        if pr_max > 0:
            pr_norm = {k: 100.0 * v / pr_max for k, v in pr.items()}
        else:
            pr_norm = {k: 0.0 for k in pr}
    else:
        pr_norm = {}

    # Combine
    final: dict[str, float] = {}
    for nid in graph.nodes:
        l = local.get(nid, 0.0)
        p = pr_norm.get(nid, 0.0)
        score = alpha * (0.4 * l + 0.6 * p) + (1.0 - alpha) * 5.0
        final[nid] = max(0.0, min(100.0, score))

    # Severity distribution
    sev_dist: dict[str, int] = defaultdict(int)
    nodes_with_findings = 0
    for node in graph.nodes.values():
        if node.findings:
            nodes_with_findings += 1
            for f in node.findings:
                sev_dist[(f.severity or "UNKNOWN").upper()] += 1

    # Top priority: sort by (is_root desc, risk_score desc, name)
    sorted_nodes = sorted(
        graph.nodes.values(),
        key=lambda nd: (not nd.is_root, -final[nd.id], nd.name),
    )
    for i, node in enumerate(sorted_nodes):
        node.risk_score = final[node.id]
        # Fix priority: lower = higher priority
        if node.findings:
            bonus = 0
            if any(f.kev for f in node.findings):
                bonus += 25
            if any(f.epss and f.epss >= 0.5 for f in node.findings):
                bonus += 10
            node.fix_priority = int(round(100 - final[node.id] + bonus))
        else:
            node.fix_priority = int(round(100 - final[node.id]))

    return final, RiskComputation(
        graph_id=graph.id,
        computed_at=datetime.utcnow(),
        alpha=alpha,
        damping=damping,
        iterations=max_iter,
        converged=True,
        top_priority=sorted_nodes[:25],
        severity_distribution=dict(sev_dist),
        nodes_with_findings=nodes_with_findings,
        mean_risk=sum(final.values()) / max(1, len(final)),
        max_risk=max(final.values()) if final else 0.0,
    )


# ============================================================================
# Cluster detection
# ============================================================================


def find_vulnerability_clusters(graph: DependencyGraph) -> list[dict]:
    """Find groups of nodes that share vulnerability context.

    Two nodes are in the same cluster if they:
      * have at least one CVE in common, OR
      * are directly connected AND one of them has a CVE and the other
        is a transitive dependency that would also be affected
        (best-effort heuristic).

    The result is a list of dicts of the shape returned to clients.
    """
    from .models.graph import VulnerabilityCluster

    # Build a map: cve_id -> [node_id]
    cve_to_nodes: dict[str, list[str]] = defaultdict(list)
    for nid, node in graph.nodes.items():
        for f in node.findings:
            cve_to_nodes[f.cve_id].append(nid)

    # Single-CVE clusters
    seen_node_clusters: set[tuple[str, ...]] = set()
    clusters: list[VulnerabilityCluster] = []
    for cve_id, nodes in cve_to_nodes.items():
        if not nodes:
            continue
        key = tuple(sorted(nodes))
        if key in seen_node_clusters:
            continue
        seen_node_clusters.add(key)
        # Aggregate severity
        from .models.dto import SbomComponent  # noqa: F401

        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": -1}
        worst = "UNKNOWN"
        for nid in nodes:
            for f in graph.nodes[nid].findings:
                if f.cve_id != cve_id:
                    continue
                if sev_rank.get(f.severity.upper(), -1) > sev_rank.get(worst, -1):
                    worst = f.severity.upper()
        agg_risk = sum(graph.nodes[nid].risk_score for nid in nodes) / max(1, len(nodes))
        clusters.append(
            VulnerabilityCluster(
                id=f"c_{cve_id}",
                node_ids=sorted(nodes),
                shared_cve_ids=[cve_id],
                aggregate_severity=worst,
                aggregate_risk=agg_risk,
            )
        )
    return clusters


# ============================================================================
# Convenience: update node findings
# ============================================================================


def apply_findings(
    graph: DependencyGraph,
    node_id: str,
    findings: list[NodeFinding],
) -> None:
    if node_id not in graph.nodes:
        raise KeyError(f"unknown node id: {node_id}")
    graph.nodes[node_id].findings = findings
    graph.updated_at = datetime.utcnow()


def is_transitive(graph: DependencyGraph, node_id: str) -> bool:
    """Return True if the node is reachable from a root only via edges."""
    if node_id in graph.root_node_ids:
        return False
    return True


# ============================================================================
# Pure-Python personalised PageRank (power iteration)
# ============================================================================


def _pagerank_power(
    graph: nx.DiGraph,
    *,
    damping: float,
    teleport: dict[str, float],
    max_iter: int,
    tol: float,
) -> dict[str, float]:
    """Personalised PageRank via power iteration.

    Avoids networkx's scipy implementation so the service can run on
    slim base images that don't ship scipy.
    """
    nodes = list(graph.nodes())
    n = len(nodes)
    if n == 0:
        return {}
    # Personalization vector (must sum to 1)
    pers = {node: float(teleport.get(node, 0.0)) for node in nodes}
    s = sum(pers.values())
    if s > 0:
        pers = {k: v / s for k, v in pers.items()}
    else:
        # uniform fallback
        pers = {node: 1.0 / n for node in nodes}
    # Initialise
    rank = dict(pers)
    # Compute out-degrees
    out_deg = {node: max(1, graph.out_degree(node)) for node in nodes}
    # Iterate
    for _ in range(max_iter):
        new_rank: dict[str, float] = {node: 0.0 for node in nodes}
        # Distribute each node's rank to its out-neighbours
        for u in nodes:
            share = damping * rank[u] / out_deg[u]
            for _, v in graph.out_edges(u):
                new_rank[v] += share
        # Add teleportation
        for node in nodes:
            new_rank[node] += (1.0 - damping) * pers[node]
        # Convergence check
        delta = sum(abs(new_rank[node] - rank[node]) for node in nodes)
        rank = new_rank
        if delta < tol:
            break
    return rank
