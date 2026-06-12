"""Unified vulnerability data model for vuln-intel.

This module defines the canonical, source-agnostic representation of a
vulnerability. The schema is intentionally aligned with the public CVE 5.0
record format (`cve.org`) so that downstream consumers (compliance,
risk layer, UI) can map it to MITRE / CVE.org without translation.

The model is implemented with Pydantic v2 for strong validation, JSON
schema export, and compatibility with FastAPI's request / response
handling.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


# ============================================================================
# Enumerations
# ============================================================================


class SeverityQualitative(StrEnum):
    """Standard qualitative severity buckets (CVSS v3.x convention)."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class SourceName(StrEnum):
    """Supported vulnerability data sources."""

    NVD = "nvd"
    GHSA = "ghsa"
    OSV = "osv"


class ScoreSource(StrEnum):
    """Origin of a severity / CVSS score."""

    NVD_PRIMARY = "nvd:primary"
    NVD_SECONDARY = "nvd:secondary"
    GHSA = "ghsa"
    OSV = "osv"
    DERIVED = "derived"


# ============================================================================
# Score fragments
# ============================================================================


class CvssScore(BaseModel):
    """A single CVSS score + vector string.

    The vector string is preserved verbatim because the score can be a
    CVSS 3.0, 3.1, or 4.0 record depending on the source. We keep
    ``version`` so downstream code can branch without parsing the
    vector.
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal["2.0", "3.0", "3.1", "4.0"] = Field(...)
    vector: str = Field(..., min_length=1, max_length=512)
    score: float = Field(..., ge=0.0, le=10.0)
    severity: SeverityQualitative
    source: ScoreSource

    @field_validator("vector")
    @classmethod
    def _vector_non_trivial(cls, v: str) -> str:
        if not v.startswith("CVSS:"):
            raise ValueError("CVSS vector must begin with 'CVSS:'")
        return v


class EpssScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) record."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(..., ge=0.0, le=1.0, description="Probability of exploit in next 30 days")
    percentile: float = Field(..., ge=0.0, le=1.0, description="Relative ranking 0..1")
    fetched_at: datetime


class KevEntry(BaseModel):
    """CISA Known Exploited Vulnerabilities entry."""

    model_config = ConfigDict(extra="forbid")

    exploited: bool = True
    date_added: datetime | None = None
    due_date: datetime | None = None
    ransomware_use: bool | None = None
    notes: str | None = None


class SeverityAggregate(BaseModel):
    """All severity signals we know about a CVE, plus the chosen one."""

    model_config = ConfigDict(extra="forbid")

    qualitative: SeverityQualitative
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    cvss_v2: CvssScore | None = None
    primary_source: ScoreSource
    rationale: str | None = None


# ============================================================================
# Affected packages
# ============================================================================


class AffectedVersionRange(BaseModel):
    """A single version range inside an affected package.

    The two ``introduced`` / ``introduced_at`` fields are deliberately
    separate (per FullstackEngineer Pydantic↔Zod alignment, 2026-06-12):

    * ``introduced_in`` — the *version* (semver string) at which the
      vulnerable range starts. Per-version, per-affected-entry.
    * ``introduced_at`` — the *deploy* (ISO-8601 timestamp) at which
      the package was first deployed into the affected range.
      Per-deploy, per-affected-entry. Internal-only — does NOT appear
      on the GitOps wire format (see GitOpsManager sign-off 2026-06-12).

    OSV-style ``fixed`` / ``last_affected`` are also supported so we
    can express "from this version onwards" (``introduced_in`` only)
    and "up to but not including this version" (``fixed`` only).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    introduced_in: str | None = Field(
        default=None,
        max_length=128,
        description="Per-version semver at which the vulnerable range starts.",
    )
    introduced_at: datetime | None = Field(
        default=None,
        description="Per-deploy ISO-8601 timestamp at which the package "
        "was first deployed into the affected range. Internal only.",
    )
    fixed: str | None = Field(default=None, max_length=128)
    last_affected: str | None = Field(default=None, max_length=128)

    @field_validator("introduced_in", "fixed", "last_affected")
    @classmethod
    def _no_whitespace(cls, v: str | None) -> str | None:
        return v.strip() if v is not None else None


class AffectedPackage(BaseModel):
    """A single package affected by a vulnerability.

    At minimum we need an ecosystem + name to match. ``purl`` is the
    canonical identifier that the dependency-intel service uses.
    """

    model_config = ConfigDict(extra="forbid")

    purl: str | None = Field(default=None, max_length=512)
    ecosystem: str | None = Field(default=None, max_length=64)
    name: str = Field(..., min_length=1, max_length=214)
    package_manager: str | None = Field(default=None, max_length=64)
    versions: list[AffectedVersionRange] = Field(default_factory=list)
    default_status: Literal["affected", "unaffected", "unknown"] = "unknown"

    @field_validator("purl")
    @classmethod
    def _purl_format(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith("pkg:"):
            raise ValueError("Package URL (purl) must start with 'pkg:'")
        return v


# ============================================================================
# References and CWE
# ============================================================================


class Reference(BaseModel):
    """A URL associated with a vulnerability."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., max_length=2048)
    type: str | None = Field(default=None, max_length=64)
    tags: list[str] = Field(default_factory=list)


# ============================================================================
# The unified CveRecord
# ============================================================================


class CveRecord(BaseModel):
    """Canonical, source-agnostic vulnerability record.

    Sources (NVD, GHSA, OSV) each produce their own internal
    representation; this class is what survives once they are
    normalized.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # --- identity -----------------------------------------------------------
    id: str = Field(..., min_length=3, max_length=64, description="CVE-YYYY-NNNN[ NNNN] preferred")
    aliases: list[str] = Field(default_factory=list, description="Alternate IDs from other sources")
    source: list[SourceName] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list, description="Snyk, OSV-only refs, etc.")

    # --- timestamps ---------------------------------------------------------
    published: datetime | None = None
    modified: datetime | None = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    # --- text ---------------------------------------------------------------
    summary: str | None = Field(default=None, max_length=2048)
    details: str | None = None

    # --- severity / exploit signals ----------------------------------------
    severity: SeverityAggregate
    epss: EpssScore | None = None
    kev: KevEntry | None = None

    # --- technical ----------------------------------------------------------
    affected: list[AffectedPackage] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    cwes: list[int] = Field(default_factory=list, description="CWE-IDs (numeric part only)")

    # --- provenance ---------------------------------------------------------
    raw: dict[str, Any] = Field(default_factory=dict, description="Original source payloads (truncated)")

    # --- S2.8: cross-source consensus + pre-actionable gate -----------------
    # S2.8 O-3.7: GitOpsManager added ``consensus_sources`` to the
    # 19-field wire format. We populate it after every ingest run from
    # the ``_sources_seen`` set maintained by the service. The list
    # contains the source names (nvd, ghsa, osv) that corroborated
    # this (CVE, package) pair — not just the CVE. The security-service
    # :4003 projection uses ``length(consensus_sources) >= 2`` as
    # the O-3.6 4-condition ``auto_actionable`` gate.
    consensus_sources: list[str] = Field(
        default_factory=list,
        description="Source identifiers that confirmed this (CVE, package) pair. "
        "REQUIRED non-empty on the GitOps wire (O-3.7 19-field schema).",
    )

    # S2.8: internal pre-actionable flag, never emitted on the wire.
    # The wire ``auto_actionable`` is computed by security-service
    # :4003 (vuln-projection.ts) as the LOCKED 4-condition AND:
    #   (kev OR (severity in {high, critical} AND epss >= 0.36))
    #     AND length(consensus_sources) >= 2
    #     AND has_reachable_fix(fixed_in, package)
    #     AND in_graph == true
    # The first AND third conditions are computable inside vuln-intel
    # and stored here as ``vuln_intel_pre_actionable`` for operator
    # alerting (Logfire / Grafana) and as a hint to the dependency-intel
    # service. The second and fourth conditions require graph state
    # owned by security-service, so it owns the wire flag.
    vuln_intel_pre_actionable: bool | None = Field(
        default=None,
        description="Internal pre-actionable hint: (kev OR (high/critical AND epss >= 0.36)) "
        "AND fix_available. Never emitted on the wire — security-service owns auto_actionable.",
    )

    # ----------------------------------------------------------------- helpers
    @property
    def primary_id(self) -> str:
        """Return the canonical id (always the CVE-* when present)."""
        return self.id

    @property
    def is_critical(self) -> bool:
        return self.severity.qualitative == SeverityQualitative.CRITICAL

    @property
    def is_exploited(self) -> bool:
        return bool(self.kev and self.kev.exploited) or bool(self.epss and self.epss.score >= 0.5)

    def add_alias(self, alias: str) -> None:
        if alias and alias != self.id and alias not in self.aliases:
            self.aliases.append(alias)

    def merge(self, other: "CveRecord") -> "CveRecord":
        """Merge two records representing the same vulnerability.

        Used when a CVE is found by more than one source (e.g. NVD and
        GHSA). The merge prefers:
          - earlier published timestamp
          - later modified timestamp
          - more recent ingested_at
          - the union of aliases, affected packages, references, cwes
          - higher-priority severity
        """
        if self.id != other.id:
            # If ``other`` has the CVE id as an alias, promote it.
            if self.id in other.aliases:
                self, other = other, self
            elif other.id in self.aliases:
                pass
            else:
                # cannot merge records with different primary ids
                raise ValueError(
                    f"cannot merge CveRecords with different primary ids: {self.id} != {other.id}"
                )

        # timestamps
        if self.published is None or (other.published and other.published < self.published):
            self.published = other.published
        if self.modified is None or (other.modified and other.modified > self.modified):
            self.modified = other.modified
        self.ingested_at = max(self.ingested_at, other.ingested_at)

        # text
        if not self.summary and other.summary:
            self.summary = other.summary
        if not self.details and other.details:
            self.details = other.details

        # severity — take the higher qualitative
        order = {
            SeverityQualitative.UNKNOWN: -1,
            SeverityQualitative.NONE: 0,
            SeverityQualitative.LOW: 1,
            SeverityQualitative.MEDIUM: 2,
            SeverityQualitative.HIGH: 3,
            SeverityQualitative.CRITICAL: 4,
        }
        if order[other.severity.qualitative] > order[self.severity.qualitative]:
            self.severity = other.severity
        # also keep alternative CVSS scores
        if other.severity.cvss_v3 and not self.severity.cvss_v3:
            self.severity.cvss_v3 = other.severity.cvss_v3
        if other.severity.cvss_v4 and not self.severity.cvss_v4:
            self.severity.cvss_v4 = other.severity.cvss_v4

        # EPSS / KEV
        if other.epss and (not self.epss or other.epss.fetched_at > self.epss.fetched_at):
            self.epss = other.epss
        if other.kev and (not self.kev or other.kev.exploited):
            self.kev = other.kev

        # union of aliases, source, related, affected, references, cwes
        for a in other.aliases:
            self.add_alias(a)
        for s in other.source:
            if s not in self.source:
                self.source.append(s)
        for r in other.related:
            if r not in self.related:
                self.related.append(r)
        for ap in other.affected:
            if not any(a.purl and a.purl == ap.purl for a in self.affected):
                self.affected.append(ap)
        for ref in other.references:
            if not any(r.url == ref.url for r in self.references):
                self.references.append(ref)
        for cwe in other.cwes:
            if cwe not in self.cwes:
                self.cwes.append(cwe)

        # raw payloads
        for k, v in other.raw.items():
            self.raw.setdefault(k, v)

        return self
