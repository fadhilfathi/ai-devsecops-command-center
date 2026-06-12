"""Graph data model for dependency-intel.

We model a SBOM-derived dependency graph as a typed :class:`DependencyGraph`.
A graph has nodes (one per package) and edges (one per declared
dependency relation). Each node carries vulnerability findings pulled
from vuln-intel (S2.2) plus a derived risk score and fix priority.

The schema is intentionally separate from the Node- and TypeScript-side
``backend/models/security/dependency-graph.model.ts`` (S2.4) because the
two services speak different transports. The conversion happens at the
S2.5 API boundary.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Enumerations
# ============================================================================


class EdgeKind(StrEnum):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    BUILD = "build"
    TEST = "test"
    UNKNOWN = "unknown"


class GraphNodeKind(StrEnum):
    APPLICATION = "application"
    LIBRARY = "library"
    FRAMEWORK = "framework"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    CONTAINER = "container"
    FILE = "file"
    UNKNOWN = "unknown"


# ============================================================================
# Findings — small projection of the CveRecord
# ============================================================================


class NodeFinding(BaseModel):
    """A single vulnerability finding attached to a graph node."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = False
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    matched_by: str | None = Field(default=None, description="purl|ecosystem+name")
    notes: str | None = None


# ============================================================================
# Nodes & edges
# ============================================================================


class GraphNode(BaseModel):
    """A single package / component node."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=512)
    purl: str | None = None
    ecosystem: str | None = None
    name: str = Field(..., min_length=1, max_length=214)
    version: str | None = None
    kind: GraphNodeKind = GraphNodeKind.LIBRARY
    is_direct: bool = False
    is_root: bool = False
    sbom_ids: list[str] = Field(default_factory=list)
    findings: list[NodeFinding] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    fix_priority: int = Field(default=0, ge=0)
    direct_dependents: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("purl")
    @classmethod
    def _purl_format(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith("pkg:"):
            raise ValueError("purl must start with 'pkg:'")
        return v


class GraphEdge(BaseModel):
    """A directed edge: ``from`` depends on ``to``."""

    model_config = ConfigDict(extra="forbid")

    from_node: str = Field(..., alias="from", min_length=1)
    to_node: str = Field(..., alias="to", min_length=1)
    kind: EdgeKind = EdgeKind.RUNTIME
    scope: str | None = None
    weight: float = Field(default=1.0, ge=0.0, le=100.0)
    properties: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)  # type: ignore[assignment]


# ============================================================================
# Vulnerability clusters
# ============================================================================


class VulnerabilityCluster(BaseModel):
    """A group of packages that share a common vulnerability context."""

    model_config = ConfigDict(extra="forbid")

    id: str
    node_ids: list[str]
    shared_cve_ids: list[str]
    aggregate_severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    aggregate_risk: float = Field(..., ge=0.0, le=100.0)


# ============================================================================
# The graph itself
# ============================================================================


class DependencyGraph(BaseModel):
    """A complete dependency graph for one or more SBOMs."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _id())
    name: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    sbom_ids: list[str] = Field(default_factory=list)
    nodes: dict[str, GraphNode] = Field(default_factory=dict)
    edges: list[GraphEdge] = Field(default_factory=list)
    root_node_ids: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def node_ids(self) -> list[str]:
        return list(self.nodes.keys())


def _id() -> str:
    import os
    return "g_" + hashlib.sha1(os.urandom(8)).hexdigest()[:12]


# ============================================================================
# Risk / priority computation result
# ============================================================================


class RiskComputation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    computed_at: datetime
    alpha: float
    damping: float
    iterations: int
    converged: bool
    top_priority: list[GraphNode] = Field(default_factory=list)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    nodes_with_findings: int = 0
    mean_risk: float = 0.0
    max_risk: float = 0.0
