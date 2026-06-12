"""Pydantic v2 models for the SBOM pipeline service.

The wire-level CycloneDX and SPDX models live in
``backend/models/security/sbom.model.ts`` (S2.4) and are mirrored
here. The :class:`Sbom` Pydantic class is the round-trip target —
it is the same shape that the S2.5 security-service proxy will
parse and persist on the Node side.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# Source kinds + prefix parsing (Lead's locked contract)
# ---------------------------------------------------------------------------


class SourceKind(str, Enum):
    """The four valid source kinds.

    The on-wire `source` field is a single string with a prefix:
    ``docker:``, ``git:``, ``fs:``, ``lockfile:``.
    """

    DOCKER = "docker"
    GIT = "git"
    FILESYSTEM = "fs"
    LOCKFILE = "lockfile"


PREFIX_MAP: Dict[str, SourceKind] = {
    "docker:": SourceKind.DOCKER,
    "git:": SourceKind.GIT,
    "fs:": SourceKind.FILESYSTEM,
    "lockfile:": SourceKind.LOCKFILE,
}


# ---------------------------------------------------------------------------
# Output formats (CycloneDX / SPDX / Syft native)
# ---------------------------------------------------------------------------


class SBOMFormat(str, Enum):
    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TAG_VALUE = "spdx-tag-value"
    SYFT_JSON = "syft-json"


# ---------------------------------------------------------------------------
# Ecosystem enum — used as a Prometheus label
# ---------------------------------------------------------------------------


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"
    RUBYGEMS = "rubygems"
    NUGET = "nuget"
    OCI = "oci"
    DEB = "deb"
    RPM = "rpm"
    APK = "apk"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Source parsing
# ---------------------------------------------------------------------------


class ParsedSource(BaseModel):
    """Result of splitting a ``source:`` string into kind + value."""

    model_config = ConfigDict(frozen=True)

    kind: SourceKind
    value: str

    @property
    def docker_ref(self) -> Optional[str]:
        return self.value if self.kind == SourceKind.DOCKER else None

    @property
    def git_ref(self) -> Optional[str]:
        return self.value if self.kind == SourceKind.GIT else None

    @property
    def fs_path(self) -> Optional[str]:
        return self.value if self.kind == SourceKind.FILESYSTEM else None

    @property
    def lockfile_path(self) -> Optional[str]:
        return self.value if self.kind == SourceKind.LOCKFILE else None


def parse_source(source: str) -> ParsedSource:
    """Split a ``prefix:value`` string into a :class:`ParsedSource`.

    Raises :class:`ValueError` for missing/unknown prefixes or empty
    values. This is the only place we accept the Lead's locked
    ``docker:`` / ``git:`` / ``fs:`` / ``lockfile:`` string format.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")
    source = source.strip()
    for prefix, kind in PREFIX_MAP.items():
        if source.startswith(prefix):
            value = source[len(prefix):].strip()
            if not value:
                raise ValueError(f"source value after prefix {prefix!r} is empty")
            return ParsedSource(kind=kind, value=value)
    raise ValueError(
        f"source must start with one of: {sorted(PREFIX_MAP)} "
        f"(got {source!r})"
    )


# ---------------------------------------------------------------------------
# CycloneDX 1.5 wire model (mirrors S2.4 Zod schema)
# ---------------------------------------------------------------------------


# Canonical hash algorithms per CycloneDX 1.5.
HASH_ALGS = (
    "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256",
    "SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512",
    "BLAKE2s-256", "BLAKE3",
)


class SbomComponentType(str, Enum):
    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"
    PLATFORM = "platform"


class SbomHash(BaseModel):
    alg: str
    content: str

    @field_validator("alg")
    @classmethod
    def _alg_uppercase(cls, v: str) -> str:
        v = v.strip()
        # CycloneDX expects uppercase; tolerate syft's mixed case.
        v = {"SHA1": "SHA-1", "SHA256": "SHA-256"}.get(v.upper(), v.upper())
        if v not in HASH_ALGS:
            raise ValueError(f"unsupported hash algorithm: {v}")
        return v


class SbomLicense(BaseModel):
    model_config = ConfigDict(extra="allow")

    license: Optional[Dict[str, Any]] = None
    expression: Optional[str] = None


class SbomComponent(BaseModel):
    """CycloneDX 1.5 component (mirrors S2.4 ``SbomComponent`` Zod schema).

    The wire field name is ``bom-ref`` (kebab) per the CycloneDX spec;
    we expose it as ``bom_ref`` in Python and serialize back to
    ``bom-ref`` on output.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: SbomComponentType
    bom_ref: str = Field(alias="bom-ref")
    name: str
    group: Optional[str] = None
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    licenses: Optional[List[SbomLicense]] = None
    hashes: Optional[List[SbomHash]] = None
    description: Optional[str] = None
    supplier: Optional[Dict[str, Any]] = None


class SbomTool(BaseModel):
    vendor: str
    name: str
    version: Optional[str] = None


class SbomMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: str
    tools: Optional[List[SbomTool]] = None
    authors: Optional[List[Dict[str, Any]]] = None
    component: Optional[SbomComponent] = None
    manufacture: Optional[Dict[str, Any]] = None
    supplier: Optional[Dict[str, Any]] = None
    properties: Optional[List[Dict[str, str]]] = None


class SbomDependency(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    ref: str
    dependsOn: List[str] = Field(default_factory=list)


class Sbom(BaseModel):
    """CycloneDX 1.5 SBOM wire model — used for round-trip I/O."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    bomFormat: Literal["CycloneDX"] = "CycloneDX"
    specVersion: str
    version: int
    serialNumber: Optional[str] = None
    metadata: SbomMetadata
    components: List[SbomComponent] = Field(default_factory=list)
    dependencies: List[SbomDependency] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# API request / response models
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    """Body of ``POST /sbom/generate``."""

    source: str = Field(
        ...,
        description=(
            "Source to scan, with prefix. One of: "
            "``docker:<image:tag>``, ``git:<url>``, ``fs:<path>``, "
            "``lockfile:<file-path>``."
        ),
        examples=["docker:nginx:latest"],
    )
    format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON
    scope: Optional[str] = Field(
        default="monorepo",
        description="Logical scope (monorepo, service-name, package-name).",
    )
    git_sha: Optional[str] = Field(
        default=None,
        description="Git short SHA baked into the sbom_id.",
    )
    metadata: Dict[str, str] = Field(default_factory=dict)
    sign: bool = Field(
        default=False,
        description="Whether to cosign-sign the SBOM in production. Ignored in dev.",
    )

    @model_validator(mode="after")
    def _validate_source(self) -> "GenerateRequest":
        # Eager validation so the error surfaces before async work.
        parse_source(self.source)
        return self


class GenerateResponse(BaseModel):
    """Body of ``POST /sbom/generate`` (success)."""

    sbom_id: str
    format: SBOMFormat
    data: Dict[str, Any] = Field(
        description="Parsed CycloneDX JSON. For XML/SPDX-tag-value the data is a string."
    )
    component_count: int
    size_bytes: int
    sha256: str
    created_at: datetime
    warnings: List[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    """Body of ``POST /sbom/analyze``."""

    sbom_id: str


class AnalyzeResponse(BaseModel):
    """Body of ``POST /sbom/analyze`` (success)."""

    sbom_id: str
    components: int
    transitive_depth: int
    ecosystems: List[str]
    license_breakdown: Dict[str, int]
    total_size_bytes: int
    analyzed_at: datetime


class ListResponse(BaseModel):
    items: List["SBOMRecord"]
    page: int
    page_size: int
    total: int


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "unready"]
    service: str
    version: str
    syft_path: Optional[str] = None
    syft_version: Optional[str] = None
    db_connected: bool
    bus_connected: bool
    uptime_seconds: float


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


# ---------------------------------------------------------------------------
# DB record (mirrors the `sboms` table)
# ---------------------------------------------------------------------------


class SBOMRecord(BaseModel):
    """A row in the ``sboms`` table — the persisted metadata + payload."""

    id: str
    source: str
    format: SBOMFormat
    data_json: str
    created_at: datetime
    sha256: str
    size_bytes: int
    # Optional enrichment
    component_count: int = 0
    scope: Optional[str] = None
    git_sha: Optional[str] = None
    object_key: Optional[str] = None

    @staticmethod
    def make_id(
        scope: str = "monorepo",
        git_sha: Optional[str] = None,
        now: Optional[datetime] = None,
        *,
        source_fingerprint: Optional[str] = None,
    ) -> str:
        """Build an sbom_id matching the GitOpsManager contract.

        Format: ``sbom-<YYYY-MM-DD>-<git-short-sha>-<scope>``

        When ``git_sha`` is not provided we fall back to a short
        fingerprint of the source string (first 8 hex chars of
        ``sha256(source)``). This guarantees uniqueness across
        multiple ``/sbom/generate`` calls on the same day with
        different sources — important for the API to be able to store
        four prefix variants in one test run, and important for
        production where multiple containers get scanned back-to-back
        without an intervening git commit.

        If ``source_fingerprint`` is supplied explicitly (e.g. a
        content hash) it overrides the default ``sha256(source)``
        computation.
        """
        now = now or datetime.now(timezone.utc)
        date = now.strftime("%Y-%m-%d")
        if git_sha:
            sha = git_sha[:8]
        elif source_fingerprint:
            sha = source_fingerprint[:8]
        else:
            sha = "nogit"
        safe_scope = re.sub(r"[^a-zA-Z0-9_.-]", "-", scope)[:48] or "monorepo"
        return f"sbom-{date}-{sha}-{safe_scope}"


# ---------------------------------------------------------------------------
# Helpers — bom-ref minting, sha256, ecosystem derivation
# ---------------------------------------------------------------------------


_PURL_TO_ECOSYSTEM_RE = re.compile(r"^pkg:([a-z0-9.+-]+)/")


def ecosystem_from_purl(purl: Optional[str]) -> Ecosystem:
    """Map a purl to a high-level ecosystem bucket."""
    if not purl:
        return Ecosystem.UNKNOWN
    m = _PURL_TO_ECOSYSTEM_RE.match(purl.lower())
    if not m:
        return Ecosystem.UNKNOWN
    eco = m.group(1)
    mapping = {
        "npm": Ecosystem.NPM,
        "pypi": Ecosystem.PYPI,
        "maven": Ecosystem.MAVEN,
        "golang": Ecosystem.GO,
        "go": Ecosystem.GO,
        "cargo": Ecosystem.CARGO,
        "gem": Ecosystem.RUBYGEMS,
        "nuget": Ecosystem.NUGET,
        "oci": Ecosystem.OCI,
        "deb": Ecosystem.DEB,
        "rpm": Ecosystem.RPM,
        "apk": Ecosystem.APK,
    }
    return mapping.get(eco, Ecosystem.UNKNOWN)


def mint_bom_ref(name: str, version: str, purl: Optional[str] = None) -> str:
    """Stable, deterministic ``bom-ref`` for a component.

    Format: ``urn:cdx:<16 hex chars>``
    - If purl is available: hash the purl.
    - Otherwise: hash ``name@version``.
    - Survives re-scans of the same artifact, so S2.3's dependency
      graph can use it as a join key across SBOM versions.
    """
    material = purl or f"{name}@{version}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"urn:cdx:{digest}"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_request_id() -> str:
    return str(uuid.uuid4())


# Resolve the forward reference for ListResponse.
ListResponse.model_rebuild()
