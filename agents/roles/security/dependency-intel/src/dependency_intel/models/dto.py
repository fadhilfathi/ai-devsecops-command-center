"""Request / response DTOs for dependency-intel."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .graph import DependencyGraph, RiskComputation, VulnerabilityCluster


# ============================================================================
# SBOM ingest request
# ============================================================================


class SbomComponent(BaseModel):
    """A single component from an SBOM (CycloneDX or SPDX-shaped)."""

    model_config = ConfigDict(extra="forbid")

    purl: str | None = None
    ecosystem: str | None = None
    name: str = Field(..., min_length=1, max_length=214)
    version: str | None = None
    kind: str | None = None
    is_direct: bool = False
    is_root: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)


class SbomDependency(BaseModel):
    """A single declared dependency relation."""

    model_config = ConfigDict(extra="forbid")

    from_ref: str = Field(..., min_length=1, description="component purl or bom-ref")
    to_ref: str = Field(..., min_length=1)
    kind: str | None = "runtime"
    scope: str | None = None


class SbomIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sbom_id: str = Field(..., min_length=1, max_length=128)
    name: str | None = None
    components: list[SbomComponent] = Field(..., min_length=1, max_length=200_000)
    dependencies: list[SbomDependency] = Field(default_factory=list, max_length=500_000)
    workspace: bool = Field(default=False, description="merge with existing graphs that share ids")


class SbomIngestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    sbom_id: str
    added_nodes: int
    added_edges: int
    skipped_nodes: int
    total_nodes: int
    total_edges: int
    took_s: float


# ============================================================================
# Graph fetch
# ============================================================================


class GraphSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str | None
    sbom_ids: list[str]
    node_count: int
    edge_count: int
    created_at: datetime
    updated_at: datetime


class GraphExportFormat(StrEnum):
    JSON = "json"
    GRAPHML = "graphml"
    DOT = "dot"


# ============================================================================
# Correlate
# ============================================================================


class CorrelateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_from_vuln_intel: bool = True
    min_severity: str = Field(default="UNKNOWN")
    exploited_only: bool = False


class CorrelateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    nodes_with_findings: int
    findings_attached: int
    severity_distribution: dict[str, int]
    took_s: float


# ============================================================================
# Risk calculation
# ============================================================================


class RiskCalculateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alpha: float | None = Field(default=None, ge=0.0, le=1.0)
    damping: float | None = Field(default=None, ge=0.0, le=1.0)
    max_iter: int = Field(default=100, ge=1, le=10_000)
    tol: float = Field(default=1e-6, ge=0.0, le=1.0)


class RiskCalculateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    result: RiskComputation
    risk_scores: dict[str, float]  # node_id -> score


# ============================================================================
# Clusters
# ============================================================================


class ClustersResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_id: str
    clusters: list[VulnerabilityCluster]
    total_clusters: int


# ============================================================================
# Errors
# ============================================================================


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["validation", "not_found", "upstream", "internal", "auth"]
    message: str
    details: dict[str, Any] | None = None
