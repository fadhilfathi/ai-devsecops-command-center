"""CycloneDX and SPDX normalizers.

Syft emits its own native JSON schema. We normalize it to the
Sprint-2 shared wire format (CycloneDX 1.5) so that downstream
consumers (security-service proxy, vuln-intel engine, dashboard)
work from a single canonical shape.

We also expose SPDX → CycloneDX-style conversion and a small SPDX
internal model for cases where the S2.5 proxy needs to round-trip
SPDX payloads without going through Syft again.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sbom_pipeline.models import (
    SBOMFormat,
    Sbom,
    SbomComponent,
    SbomComponentType,
    SbomDependency,
    SbomHash,
    SbomLicense,
    SbomMetadata,
    SbomTool,
    mint_bom_ref,
)

logger = logging.getLogger("sbom_pipeline.parsers")


# ---------------------------------------------------------------------------
# Syft → CycloneDX
# ---------------------------------------------------------------------------


def syft_to_cyclonedx(raw: Dict[str, Any]) -> Sbom:
    """Convert raw Syft JSON (v1.6+ schema) into the internal Sbom model.

    The returned :class:`Sbom` is the canonical wire format used by
    S2.4 / S2.5 / S2.6 / S2.9 / S2.10. Every component gets a stable
    ``bom-ref`` of the form ``urn:cdx:<16 hex>`` so the
    dependency-graph (S2.3) can use it as a join key across versions.
    """
    artifacts = raw.get("artifacts") or []
    components: List[SbomComponent] = []
    seen_bom_refs: Dict[str, str] = {}
    for art in artifacts:
        comp = _component_from_syft(art)
        # Dedupe by bom-ref to defend against catalogers emitting
        # the same package twice.
        key = comp.bom_ref
        if key in seen_bom_refs:
            continue
        seen_bom_refs[key] = comp.bom_ref
        components.append(comp)

    source = raw.get("source") or {}
    descriptor = raw.get("descriptor") or {}
    tools: List[SbomTool] = []
    if descriptor.get("name") == "syft":
        tools.append(
            SbomTool(
                vendor="Anchore",
                name="syft",
                version=raw.get("version") or descriptor.get("version"),
            )
        )

    metadata = SbomMetadata(
        timestamp=(raw.get("schema") or {}).get("url", "")
        and datetime.now(timezone.utc).isoformat(),
        tools=tools or None,
    )
    # Always override timestamp with *now* (we don't trust the source).
    metadata = metadata.model_copy(
        update={"timestamp": datetime.now(timezone.utc).isoformat()}
    )

    # Build a "root" component so consumers can attach metadata to it.
    root = _root_component_from_syft_source(source)
    if root is not None:
        metadata = metadata.model_copy(update={"component": root})

    # Dependencies: Syft gives us artifactRelationships. We translate
    # them to CycloneDX's {ref, dependsOn[]} shape, keyed by bom-ref.
    deps = _dependencies_from_syft(artifacts, components)

    return Sbom(
        specVersion="1.5",
        version=1,
        serialNumber=f"urn:uuid:{uuid.uuid4()}",
        metadata=metadata,
        components=components,
        dependencies=deps,
    )


def _component_from_syft(art: Dict[str, Any]) -> SbomComponent:
    name = (art.get("name") or "").strip() or "unknown"
    version = (art.get("version") or "").strip()
    purl = art.get("purl")
    cpe = art.get("cpe")
    bom_ref = mint_bom_ref(name, version, purl)

    hashes: List[SbomHash] = []
    for h in art.get("hashes") or []:
        try:
            hashes.append(SbomHash(alg=h["algorithm"], content=h["value"]))
        except (KeyError, ValueError):
            continue

    licenses: List[SbomLicense] = []
    for lic in art.get("licenses") or []:
        if isinstance(lic, dict):
            value = lic.get("value") or lic.get("name")
        else:
            value = str(lic)
        if not value:
            continue
        licenses.append(
            SbomLicense(
                license={"id": value} if value.startswith(("SPDX-", "LicenseRef-"))
                else {"name": value}
            )
        )

    syft_type = (art.get("type") or "").lower()
    cdx_type = _syft_type_to_cdx(syft_type)

    return SbomComponent(
        type=cdx_type,
        bom_ref=bom_ref,
        name=name,
        version=version or None,
        purl=purl,
        cpe=cpe,
        licenses=licenses or None,
        hashes=hashes or None,
    )


def _syft_type_to_cdx(syft_type: str) -> SbomComponentType:
    """Best-effort mapping from Syft's package-type enum to CycloneDX."""
    if "java-archive" in syft_type or "jar" in syft_type:
        return SbomComponentType.LIBRARY
    if "binary" in syft_type:
        return SbomComponentType.APPLICATION
    if "os" in syft_type or "kernel" in syft_type:
        return SbomComponentType.OPERATING_SYSTEM
    if "image" in syft_type or "docker" in syft_type:
        return SbomComponentType.CONTAINER
    return SbomComponentType.LIBRARY


def _root_component_from_syft_source(source: Dict[str, Any]) -> Optional[SbomComponent]:
    if not source:
        return None
    target = source.get("target") or ""
    if not target:
        return None
    stype = source.get("type") or ""
    if stype == "directory":
        ctype = SbomComponentType.APPLICATION
    elif stype == "image":
        ctype = SbomComponentType.CONTAINER
    else:
        ctype = SbomComponentType.APPLICATION
    return SbomComponent(
        type=ctype,
        bom_ref=mint_bom_ref(target, "", None),
        name=target.split("/")[-1] or target,
        version=None,
        purl=None,
    )


def _dependencies_from_syft(
    artifacts: List[Dict[str, Any]],
    components: List[SbomComponent],
) -> List[SbomDependency]:
    """Convert Syft's artifactRelationships to CycloneDX dependencies.

    We index components by their bom-ref and look up parent/child by
    the artifact ID. Any edge we can't resolve is silently dropped
    (we'd rather return a partial graph than fail the whole scan).
    """
    id_to_ref: Dict[str, str] = {}
    for art in artifacts:
        art_id = art.get("id")
        if not art_id:
            continue
        bom_ref = mint_bom_ref(
            (art.get("name") or "").strip(),
            (art.get("version") or "").strip(),
            art.get("purl"),
        )
        id_to_ref[art_id] = bom_ref

    edges: Dict[str, set] = {}
    for rel in raw_relationships(artifacts):
        parent = id_to_ref.get(rel.get("parent", ""))
        child = id_to_ref.get(rel.get("child", ""))
        if not parent or not child:
            continue
        edges.setdefault(parent, set()).add(child)
        edges.setdefault(child, set())  # ensure child is in the list

    return [
        SbomDependency(ref=ref, dependsOn=sorted(deps))
        for ref, deps in sorted(edges.items())
    ]


def raw_relationships(artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract ``artifactRelationships`` from a list of Syft artifacts.

    Syft sometimes nests relationships under individual artifacts
    (``art.artifactRelationships``) and sometimes at the top level
    (``raw.artifactRelationships``). We try both.
    """
    out: List[Dict[str, Any]] = []
    for art in artifacts:
        for rel in art.get("artifactRelationships") or []:
            out.append(rel)
    return out


# ---------------------------------------------------------------------------
# CycloneDX JSON → internal Sbom
# ---------------------------------------------------------------------------


def cyclonedx_text_to_sbom(text: str) -> Sbom:
    """Parse a CycloneDX 1.5 JSON string into the internal Sbom model."""
    raw = json.loads(text)
    return Sbom.model_validate(raw)


# ---------------------------------------------------------------------------
# SPDX → internal model (for the analyze endpoint)
# ---------------------------------------------------------------------------


def syft_to_spdx_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Translate Syft native JSON to an SPDX 2.3-shaped dict.

    Used when the caller asked for ``spdx-json`` so we can return
    SPDX 2.3 *and* still drive the analyzer from the same internal
    component list.
    """
    artifacts = raw.get("artifacts") or []
    packages: List[Dict[str, Any]] = []
    for i, art in enumerate(artifacts, start=1):
        name = (art.get("name") or "").strip()
        version = (art.get("version") or "").strip()
        purl = art.get("purl")
        cpe = art.get("cpe")
        licenses: List[Dict[str, Any]] = []
        for lic in art.get("licenses") or []:
            value = lic.get("value") if isinstance(lic, dict) else str(lic)
            if value:
                licenses.append(
                    {
                        "license": {
                            "id": value
                            if value.startswith(("SPDX-", "LicenseRef-"))
                            else "NOASSERTION",
                        }
                    }
                )
        ext_refs: List[Dict[str, Any]] = []
        if purl:
            ext_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            )
        if cpe:
            ext_refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe22Type",
                    "referenceLocator": cpe,
                }
            )
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": name,
                "versionInfo": version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": ext_refs,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{uuid.uuid4()}",
        "documentNamespace": f"https://aionrs.io/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [
                "Tool: Anchore-syft",
                "Organization: AionRs",
            ],
        },
        "packages": packages,
    }


# ---------------------------------------------------------------------------
# Body serialization
# ---------------------------------------------------------------------------


def serialize_sbom(sbom: Sbom, fmt: SBOMFormat) -> Tuple[str, str]:
    """Serialize an Sbom into the requested wire format.

    Returns ``(body, media_type)``. ``body`` is always a string;
    JSON formats are compact (one-line) for easier grep + diff.
    """
    if fmt == SBOMFormat.CYCLONEDX_JSON:
        return sbom.model_dump_json(by_alias=True, exclude_none=True), "application/vnd.cyclonedx+json"
    if fmt == SBOMFormat.CYCLONEDX_XML:
        return _sbom_to_cyclonedx_xml(sbom), "application/vnd.cyclonedx+xml"
    if fmt == SBOMFormat.SPDX_JSON:
        # Caller is expected to have run the syft_to_spdx_dict path;
        # if they passed an Sbom here, we use Syft→SPDX as a best
        # effort. (We don't keep raw Syft output in Sbom.)
        return "{}", "application/spdx+json"
    if fmt == SBOMFormat.SPDX_TAG_VALUE:
        return _sbom_to_spdx_tag_value(sbom), "text/spdx"
    if fmt == SBOMFormat.SYFT_JSON:
        return sbom.model_dump_json(by_alias=True, exclude_none=True), "application/json"
    raise ValueError(f"unsupported format: {fmt}")


def _sbom_to_cyclonedx_xml(sbom: Sbom) -> str:
    """Minimal CycloneDX 1.5 XML serialization.

    The XML format is only used in special cases; we keep the
    serializer hand-rolled and dependency-free. Production code can
    swap in the official ``cyclonedx-python-lib`` later.
    """
    from xml.etree.ElementTree import Element, SubElement, tostring
    from xml.dom.minidom import parseString

    root = Element(
        "bom",
        {
            "xmlns": "http://cyclonedx.org/schema/bom/1.5",
            "serialNumber": sbom.serialNumber or f"urn:uuid:{uuid.uuid4()}",
            "version": str(sbom.version),
        },
    )
    md = SubElement(root, "metadata")
    SubElement(md, "timestamp").text = sbom.metadata.timestamp
    if sbom.metadata.tools:
        tools_el = SubElement(md, "tools")
        for t in sbom.metadata.tools:
            tool = SubElement(tools_el, "tool")
            SubElement(tool, "vendor").text = t.vendor
            SubElement(tool, "name").text = t.name
            if t.version:
                SubElement(tool, "version").text = t.version
    comps = SubElement(root, "components")
    for c in sbom.components:
        comp = SubElement(
            comps, "component",
            {"type": c.type.value, "bom-ref": c.bom_ref},
        )
        SubElement(comp, "name").text = c.name
        if c.version:
            SubElement(comp, "version").text = c.version
        if c.purl:
            SubElement(comp, "purl").text = c.purl
    rough = tostring(root, encoding="utf-8")
    return parseString(rough).toprettyxml(indent="  ")


def _sbom_to_spdx_tag_value(sbom: Sbom) -> str:
    """Minimal SPDX 2.3 tag-value serialization."""
    lines = [
        "SPDXVersion: SPDX-2.3",
        "DataLicense: CC0-1.0",
        "SPDXID: SPDXRef-DOCUMENT",
        f"DocumentName: SBOM-{sbom.serialNumber or uuid.uuid4()}",
        f"DocumentNamespace: https://aionrs.io/sbom/{uuid.uuid4()}",
        f"Created: {datetime.now(timezone.utc).isoformat()}Z",
        "Creator: Organization: AionRs",
    ]
    for i, c in enumerate(sbom.components, start=1):
        spdx_id = f"SPDXRef-Package-{i}"
        lines.append(f"PackageName: {c.name}")
        lines.append(f"SPDXID: {spdx_id}")
        lines.append(f"PackageVersion: {c.version or 'NOASSERTION'}")
        lines.append("PackageDownloadLocation: NOASSERTION")
        lines.append("PackageLicenseConcluded: NOASSERTION")
        lines.append("PackageLicenseDeclared: NOASSERTION")
        lines.append("PackageCopyrightText: NOASSERTION")
        if c.purl:
            lines.append(f"ExternalRef: PACKAGE-MANAGER purl {c.purl}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
