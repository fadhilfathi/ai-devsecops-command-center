"""Request / response DTOs for the vuln-intel FastAPI surface."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .cve import CveRecord, SeverityQualitative, SourceName


# ============================================================================
# Common helpers
# ============================================================================


class IngestSourceRequest(BaseModel):
    """Request to ingest from a single source."""

    model_config = ConfigDict(extra="forbid")

    source: SourceName
    since: datetime | None = Field(
        default=None,
        description="Lower bound (modified-after). None means full sync.",
    )
    limit: int | None = Field(default=None, ge=1, le=20_000)


class IngestRequest(BaseModel):
    """Request to ingest vulnerabilities from one or more sources."""

    model_config = ConfigDict(extra="forbid")

    sources: list[SourceName] = Field(
        default_factory=lambda: [SourceName.NVD, SourceName.GHSA, SourceName.OSV],
    )
    full: bool = Field(default=False, description="If true, ignore caches and ignore ``since``")
    max_per_source: int | None = Field(default=None, ge=1, le=20_000)


class IngestResponse(BaseModel):
    """Response of an ingestion job."""

    model_config = ConfigDict(extra="forbid")

    job_id: str
    started_at: datetime
    finished_at: datetime
    duration_s: float
    requested_sources: list[SourceName]
    fetched: dict[SourceName, int] = Field(default_factory=dict)
    merged: int = 0
    skipped: int = 0
    errors: dict[SourceName, str] = Field(default_factory=dict)


# ============================================================================
# Lookup
# ============================================================================


class CveLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str] = Field(..., min_length=1, max_length=1_000)
    include_raw: bool = False


class CveLookupResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    found: list[CveRecord]
    missing: list[str]
    total: int


# ============================================================================
# Scoring
# ============================================================================


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] | None = Field(default=None, max_length=1_000)
    refresh_epss: bool = True
    refresh_kev: bool = True
    # S2.8: opt-in LLM exploit scoring. Requires the service to be
    # started with VULN_INTEL_LLM_ENABLED=1; otherwise it is a no-op
    # and EPSS continues to be the only exploit-likelihood signal.
    use_llm: bool = False
    tenant_id: str = "default"


class ScoreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scored: list[CveRecord]
    unchanged: int
    errors: list[str] = Field(default_factory=list)


# ============================================================================
# SBOM match
# ============================================================================


class MatchRequestComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purl: str | None = None
    ecosystem: str | None = None
    name: str
    version: str | None = None
    package_manager: str | None = None


class MatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    components: list[MatchRequestComponent] = Field(..., min_length=1, max_length=100_000)
    min_severity: SeverityQualitative = SeverityQualitative.UNKNOWN
    include_exploited_only: bool = False


class MatchFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component: MatchRequestComponent
    cve: CveRecord
    affected: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    notes: str | None = None


class MatchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[MatchFinding]
    total_components: int
    affected_components: int
    severity_counts: dict[SeverityQualitative, int] = Field(default_factory=dict)


# ============================================================================
# Stats
# ============================================================================


class SourceStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: SourceName
    records: int
    last_ingest_at: datetime | None
    last_error: str | None


class StatsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_records: int
    by_source: list[SourceStats]
    cache_hit_ratio: float
    kev_count: int
    epss_scored: int
    severity_distribution: dict[SeverityQualitative, int]


# ============================================================================
# Sync
# ============================================================================


class SyncOnceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[SourceName] | None = None
    full: bool = False


# ============================================================================
# Errors
# ============================================================================


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: Literal["validation", "not_found", "upstream", "internal", "auth"]
    message: str
    details: dict[str, Any] | None = None
