"""Output serializers — CycloneDX (JSON/XML) and SPDX (JSON/tag-value).

The internal :class:`SBOM` model is the single source of truth. Each
serializer converts that model into a wire format. CycloneDX is the
canonical output; SPDX is provided for downstream tooling that hasn't
adopted CycloneDX yet.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree as ET
from xml.dom import minidom

from sbom_generator.models.sbom import (
    Component,
    ExternalReference,
    Hash,
    License,
    SBOM,
    SBOMFormat,
)

# CycloneDX spec namespace — keeping it inline so that we don't take a
# dependency on the official library at this stage.
_CDX_NS = "http://cyclonedx.org/schema/bom/1.5"


# ---------------------------------------------------------------------------
# CycloneDX JSON
# ---------------------------------------------------------------------------


def to_cyclonedx_json(sbom: SBOM) -> str:
    payload = _to_cyclonedx_dict(sbom)
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _to_cyclonedx_dict(sbom: SBOM) -> Dict[str, Any]:
    components: List[Dict[str, Any]] = []
    for c in sbom.components:
        components.append(_component_to_cdx(c))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": sbom.serial_number,
        "version": sbom.version,
        "metadata": {
            "timestamp": sbom.metadata.timestamp.isoformat(),
            "tools": [
                {"vendor": t.vendor, "name": t.name, "version": t.version}
                for t in sbom.metadata.tools
            ],
            "authors": [{"name": a} for a in sbom.metadata.authors],
            "component": {
                "type": "application",
                "name": "sbom-target",
                "version": "0.0.0",
            }
            if not sbom.metadata.source_uri
            else {
                "type": "application",
                "name": sbom.metadata.source_uri,
                "version": "0.0.0",
            },
            "properties": [
                {"name": k, "value": v}
                for k, v in (sbom.metadata.properties or {}).items()  # type: ignore[attr-defined]
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": deps or []}
            for ref, deps in sbom.dependencies.items()
        ],
    }


def _component_to_cdx(c: Component) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": c.type.value,
        "bom-ref": c.bom_ref,
        "name": c.name,
    }
    if c.version:
        payload["version"] = c.version
    if c.group:
        payload["group"] = c.group
    if c.purl:
        payload["purl"] = c.purl
    if c.cpe:
        payload["cpe"] = c.cpe
    if c.description:
        payload["description"] = c.description
    if c.licenses:
        payload["licenses"] = [
            _license_to_cdx(lic) for lic in c.licenses
        ]
    if c.hashes:
        payload["hashes"] = [
            {"alg": h.algorithm.upper(), "content": h.value} for h in c.hashes
        ]
    if c.external_references:
        payload["externalReferences"] = [
            _extref_to_cdx(r) for r in c.external_references
        ]
    if c.properties:
        payload["properties"] = [
            {"name": k, "value": v} for k, v in c.properties.items()
        ]
    return payload


def _license_to_cdx(lic: License) -> Dict[str, Any]:
    if lic.id:
        return {"license": {"id": lic.id}}
    if lic.name:
        return {"license": {"name": lic.name}}
    if lic.expression:
        return {"expression": lic.expression}
    return {}


def _extref_to_cdx(r: ExternalReference) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": r.type, "url": r.url}
    if r.comment:
        out["comment"] = r.comment
    return out


# ---------------------------------------------------------------------------
# CycloneDX XML
# ---------------------------------------------------------------------------


def to_cyclonedx_xml(sbom: SBOM) -> str:
    root = ET.Element(
        "bom",
        {
            "xmlns": _CDX_NS,
            "serialNumber": sbom.serial_number,
            "version": str(sbom.version),
        },
    )
    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(metadata, "timestamp").text = sbom.metadata.timestamp.isoformat()
    tools = ET.SubElement(metadata, "tools")
    for t in sbom.metadata.tools:
        tool = ET.SubElement(tools, "tool")
        if t.vendor:
            ET.SubElement(tool, "vendor").text = t.vendor
        if t.name:
            ET.SubElement(tool, "name").text = t.name
        if t.version:
            ET.SubElement(tool, "version").text = t.version
    components = ET.SubElement(root, "components")
    for c in sbom.components:
        comp = ET.SubElement(components, "component", {"type": c.type.value, "bom-ref": c.bom_ref})
        ET.SubElement(comp, "name").text = c.name
        if c.version:
            ET.SubElement(comp, "version").text = c.version
        if c.purl:
            ET.SubElement(comp, "purl").text = c.purl
        if c.cpe:
            ET.SubElement(comp, "cpe").text = c.cpe
        if c.licenses:
            licenses = ET.SubElement(comp, "licenses")
            for lic in c.licenses:
                lic_el = ET.SubElement(licenses, "license")
                if lic.id:
                    ET.SubElement(lic_el, "id").text = lic.id
                elif lic.name:
                    ET.SubElement(lic_el, "name").text = lic.name
    deps = ET.SubElement(root, "dependencies")
    for ref, depends in sbom.dependencies.items():
        d = ET.SubElement(deps, "dependency", {"ref": ref})
        for child in depends or []:
            ET.SubElement(d, "dependency", {"ref": child})
    rough = ET.tostring(root, encoding="utf-8")
    return minidom.parseString(rough).toprettyxml(indent="  ")


# ---------------------------------------------------------------------------
# SPDX JSON
# ---------------------------------------------------------------------------


_SPDX_LICENSE_MAP = {
    "MIT": "MIT",
    "Apache-2.0": "Apache-2.0",
    "BSD-3-Clause": "BSD-3-Clause",
    "GPL-3.0-only": "GPL-3.0-only",
    "GPL-2.0-only": "GPL-2.0-only",
    "LGPL-2.1-only": "LGPL-2.1-only",
    "ISC": "ISC",
    "MPL-2.0": "MPL-2.0",
    "Unlicense": "Unlicense",
    "CC0-1.0": "CC0-1.0",
}


def to_spdx_json(sbom: SBOM) -> str:
    payload = _to_spdx_dict(sbom)
    return json.dumps(payload, indent=2, sort_keys=True, default=str)


def _to_spdx_dict(sbom: SBOM) -> Dict[str, Any]:
    package_index = {c.bom_ref: i + 1 for i, c in enumerate(sbom.components)}
    packages: List[Dict[str, Any]] = []
    for c in sbom.components:
        spdx_id = f"SPDXRef-Package-{package_index[c.bom_ref]}"
        license_concluded = "NOASSERTION"
        if c.licenses:
            first = c.licenses[0]
            license_concluded = first.id or first.name or first.expression or "NOASSERTION"
        pkg: Dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": c.name,
            "versionInfo": c.version or "NOASSERTION",
            # Per SPDX 2.3 downloadLocation should be a URL; we carry
            # the actual download / reference location there and
            # preserve the purl in externalRefs.
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": license_concluded,
            "licenseDeclared": license_concluded,
            "copyrightText": "NOASSERTION",
        }
        ext_refs: List[Dict[str, Any]] = []
        if c.purl:
            ext_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl,
                }
            )
        if c.cpe:
            ext_refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe22Type",
                    "referenceLocator": c.cpe,
                }
            )
        if ext_refs:
            pkg["externalRefs"] = ext_refs
        packages.append(pkg)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{sbom.serial_number}",
        "documentNamespace": sbom.serial_number,
        "creationInfo": {
            "created": sbom.metadata.timestamp.isoformat(),
            "creators": [
                f"Tool: {t.vendor}-{t.name}-{t.version}"
                for t in sbom.metadata.tools
            ] + ["Organization: AionRs"],
        },
        "packages": packages,
    }


# ---------------------------------------------------------------------------
# SPDX tag-value
# ---------------------------------------------------------------------------


def to_spdx_tag_value(sbom: SBOM) -> str:
    lines: List[str] = []
    lines.append("SPDXVersion: SPDX-2.3")
    lines.append("DataLicense: CC0-1.0")
    lines.append("SPDXID: SPDXRef-DOCUMENT")
    lines.append(f"DocumentName: SBOM-{sbom.serial_number}")
    lines.append(f"DocumentNamespace: {sbom.serial_number}")
    lines.append(f"Created: {sbom.metadata.timestamp.isoformat()}Z")
    for tool in sbom.metadata.tools:
        lines.append(f"Creator: Tool: {tool.vendor}-{tool.name}-{tool.version}")
    lines.append("Creator: Organization: AionRs")
    for i, c in enumerate(sbom.components, start=1):
        spdx_id = f"SPDXRef-Package-{i}"
        lines.append(f"PackageName: {c.name}")
        lines.append(f"SPDXID: {spdx_id}")
        lines.append(f"PackageVersion: {c.version or 'NOASSERTION'}")
        lines.append(f"PackageDownloadLocation: {c.purl or 'NOASSERTION'}")
        if c.licenses:
            lic = c.licenses[0]
            lines.append(
                f"PackageLicenseConcluded: {lic.id or lic.name or lic.expression or 'NOASSERTION'}"
            )
            lines.append(
                f"PackageLicenseDeclared: {lic.id or lic.name or lic.expression or 'NOASSERTION'}"
            )
        else:
            lines.append("PackageLicenseConcluded: NOASSERTION")
            lines.append("PackageLicenseDeclared: NOASSERTION")
        lines.append("PackageCopyrightText: NOASSERTION")
        if c.purl:
            lines.append(f"ExternalRef: PACKAGE-MANAGER purl {c.purl}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


_MEDIA_TYPES: Dict[SBOMFormat, str] = {
    SBOMFormat.CYCLONEDX_JSON: "application/vnd.cyclonedx+json",
    SBOMFormat.CYCLONEDX_XML: "application/vnd.cyclonedx+xml",
    SBOMFormat.SPDX_JSON: "application/spdx+json",
    SBOMFormat.SPDX_TAG_VALUE: "text/spdx",
    SBOMFormat.SYFT_JSON: "application/json",
}


def get_media_type(fmt: SBOMFormat) -> str:
    return _MEDIA_TYPES[fmt]


def serialize(sbom: SBOM, fmt: SBOMFormat) -> Tuple[str, str]:
    """Serialize ``sbom`` to the requested format. Returns ``(body, media)``."""
    if fmt == SBOMFormat.CYCLONEDX_JSON:
        return to_cyclonedx_json(sbom), _MEDIA_TYPES[fmt]
    if fmt == SBOMFormat.CYCLONEDX_XML:
        return to_cyclonedx_xml(sbom), _MEDIA_TYPES[fmt]
    if fmt == SBOMFormat.SPDX_JSON:
        return to_spdx_json(sbom), _MEDIA_TYPES[fmt]
    if fmt == SBOMFormat.SPDX_TAG_VALUE:
        return to_spdx_tag_value(sbom), _MEDIA_TYPES[fmt]
    if fmt == SBOMFormat.SYFT_JSON:
        return json.dumps(sbom.raw, indent=2, sort_keys=True), _MEDIA_TYPES[fmt]
    raise ValueError(f"unsupported format: {fmt}")
