"""Internal SBOM data model.

This is the canonical representation that the agent uses internally.
It is deliberately compact and language-agnostic. The CycloneDX and
SPDX serializers translate to/from this model so that the rest of the
agent does not need to know about specific output formats.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic models (used for the public API)
# ---------------------------------------------------------------------------


class ComponentType(str, Enum):
    LIBRARY = "library"
    APPLICATION = "application"
    FRAMEWORK = "framework"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"
    CONTAINER = "container"
    PLATFORM = "platform"


class SBOMFormat(str, Enum):
    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TAG_VALUE = "spdx-tag-value"
    SYFT_JSON = "syft-json"


class License(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    expression: Optional[str] = None


class Hash(BaseModel):
    algorithm: str
    value: str


class ExternalReference(BaseModel):
    type: str
    url: str
    comment: Optional[str] = None


class Component(BaseModel):
    """A normalized component entry, close to CycloneDX semantics."""

    bom_ref: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ComponentType = ComponentType.LIBRARY
    name: str
    version: str = ""
    purl: Optional[str] = None
    cpe: Optional[str] = None
    group: Optional[str] = None
    description: Optional[str] = None
    licenses: List[License] = Field(default_factory=list)
    hashes: List[Hash] = Field(default_factory=list)
    external_references: List[ExternalReference] = Field(default_factory=list)
    supplier: Optional[str] = None
    origin: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    properties: Dict[str, str] = Field(default_factory=dict)


class Tool(BaseModel):
    vendor: str
    name: str
    version: str


class SBOMMetadata(BaseModel):
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tools: List[Tool] = Field(default_factory=list)
    authors: List[str] = Field(default_factory=list)
    source_uri: Optional[str] = None
    source_type: Optional[str] = None
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None


class SBOM(BaseModel):
    """Internal SBOM model — independent of any external schema."""

    serial_number: str = Field(
        default_factory=lambda: f"urn:uuid:{uuid.uuid4()}"
    )
    version: int = 1
    metadata: SBOMMetadata = Field(default_factory=SBOMMetadata)
    components: List[Component] = Field(default_factory=list)
    dependencies: Dict[str, List[str]] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)
    format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_PURL_RE = re.compile(r"^pkg:[a-z0-9.+-]+/.+")
_CPE_RE = re.compile(r"^cpe:2\.[23]:")


def is_valid_purl(value: Optional[str]) -> bool:
    return bool(value and _PURL_RE.match(value))


def is_valid_cpe(value: Optional[str]) -> bool:
    return bool(value and _CPE_RE.match(value))


def fingerprint(component: Component) -> str:
    """Stable hash for dedupe/identity comparisons across runs."""
    h = hashlib.sha256()
    h.update(component.name.encode("utf-8"))
    h.update(b"@")
    h.update(component.version.encode("utf-8"))
    if component.purl:
        h.update(b"|")
        h.update(component.purl.encode("utf-8"))
    return h.hexdigest()


def normalize_syft_output(raw: Dict[str, Any]) -> SBOM:
    """Convert raw Syft JSON (v0.69+ schema) into the internal SBOM model."""
    artifacts = raw.get("artifacts", []) or []
    components: List[Component] = []
    for art in artifacts:
        name = art.get("name") or ""
        version = art.get("version") or ""
        if not name and not version:
            continue
        purl = art.get("purl")
        cpe = art.get("cpe")
        licenses: List[License] = []
        for lic in art.get("licenses") or []:
            value = lic.get("value") if isinstance(lic, dict) else str(lic)
            if not value:
                continue
            licenses.append(
                License(
                    id=value
                    if value.startswith(("SPDX-", "LicenseRef-"))
                    else None,
                    name=value,
                    expression=value,
                )
            )
        hashes: List[Hash] = []
        for h in art.get("hashes") or []:
            try:
                hashes.append(Hash(algorithm=h["algorithm"], value=h["value"]))
            except KeyError:
                continue
        ext_refs: List[ExternalReference] = []
        for ref in art.get("foundBy") or []:
            ext_refs.append(
                ExternalReference(
                    type="build-meta",
                    url=f"syft:foundBy:{ref}",
                    comment="Detected by Syft cataloguer",
                )
            )
        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                cpe=cpe,
                type=ComponentType.LIBRARY,
                licenses=licenses,
                hashes=hashes,
                external_references=ext_refs,
                properties={
                    "syft:layer": (art.get("layer") or {}).get("digest", ""),
                    "syft:location": (art.get("locations") or [{}])[0].get(
                        "path", ""
                    )
                    if art.get("locations")
                    else "",
                    "syft:language": art.get("language", ""),
                    "syft:type": art.get("type", ""),
                },
            )
        )

    source = raw.get("source", {}) or {}
    metadata = SBOMMetadata(
        tools=[Tool(vendor="Anchore", name="Syft", version=raw.get("version", ""))],
        source_type=source.get("type"),
        source_uri=source.get("target"),
    )

    deps: Dict[str, List[str]] = {}
    for art in artifacts:
        if not art.get("purl"):
            continue
        key = art["purl"]
        deps[key] = []

    return SBOM(
        metadata=metadata,
        components=components,
        dependencies=deps,
        raw=raw,
        format=SBOMFormat.SYFT_JSON,
    )
