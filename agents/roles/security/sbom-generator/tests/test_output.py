"""Tests for the CycloneDX / SPDX output serializers."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from sbom_generator.models.sbom import (
    Component,
    ComponentType,
    ExternalReference,
    Hash,
    License,
    SBOM,
    SBOMFormat,
    SBOMMetadata,
    Tool,
)
from sbom_generator import output as output_module


def _make_sbom() -> SBOM:
    return SBOM(
        serial_number="urn:uuid:00000000-0000-0000-0000-000000000001",
        version=1,
        metadata=SBOMMetadata(
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            tools=[Tool(vendor="Anchore", name="syft", version="1.6.0")],
            source_uri="nginx:1.25",
            source_type="docker-image",
        ),
        components=[
            Component(
                name="lodash",
                version="4.17.21",
                purl="pkg:npm/lodash@4.17.21",
                cpe="cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
                type=ComponentType.LIBRARY,
                licenses=[License(id="MIT", name="MIT License")],
                hashes=[Hash(algorithm="sha1", value="679591c564c3bffaae8454cf0b3df370c3d6911c")],
                external_references=[ExternalReference(type="documentation", url="https://lodash.com")],
            ),
            Component(
                name="requests",
                version="2.31.0",
                purl="pkg:pypi/requests@2.31.0",
                type=ComponentType.LIBRARY,
                licenses=[License(expression="Apache-2.0")],
            ),
        ],
        dependencies={
            "pkg:npm/lodash@4.17.21": [],
            "pkg:pypi/requests@2.31.0": [],
        },
    )


def test_cyclonedx_json_round_trip():
    sbom = _make_sbom()
    body = output_module.to_cyclonedx_json(sbom)
    parsed = json.loads(body)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.5"
    assert parsed["serialNumber"].endswith("000000000001")
    assert len(parsed["components"]) == 2
    assert any(c["name"] == "lodash" for c in parsed["components"])
    dep_names = {c["name"] for c in parsed["components"]}
    assert "lodash" in dep_names
    assert "requests" in dep_names


def test_cyclonedx_json_includes_dependencies():
    sbom = _make_sbom()
    parsed = json.loads(output_module.to_cyclonedx_json(sbom))
    assert isinstance(parsed["dependencies"], list)
    assert len(parsed["dependencies"]) == 2


def test_cyclonedx_xml_is_well_formed_xml():
    from xml.etree import ElementTree as ET

    sbom = _make_sbom()
    body = output_module.to_cyclonedx_xml(sbom)
    root = ET.fromstring(body)
    assert root.tag.endswith("bom")
    assert any(child.tag.endswith("components") for child in root)


def test_spdx_json_has_required_fields():
    sbom = _make_sbom()
    parsed = json.loads(output_module.to_spdx_json(sbom))
    assert parsed["spdxVersion"] == "SPDX-2.3"
    assert parsed["dataLicense"] == "CC0-1.0"
    assert parsed["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(parsed["packages"]) == 2
    pkg = parsed["packages"][0]
    assert pkg["SPDXID"].startswith("SPDXRef-Package-")
    assert "externalRefs" in pkg


def test_spdx_tag_value_basic_structure():
    sbom = _make_sbom()
    body = output_module.to_spdx_tag_value(sbom)
    assert "SPDXVersion: SPDX-2.3" in body
    assert "DataLicense: CC0-1.0" in body
    assert "PackageName: lodash" in body
    assert "PackageName: requests" in body
    assert "PackageLicenseConcluded: MIT" in body
    assert "ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21" in body


def test_serialize_dispatches_on_format():
    sbom = _make_sbom()
    for fmt, expected in [
        (SBOMFormat.CYCLONEDX_JSON, '"bomFormat": "CycloneDX"'),
        (SBOMFormat.SPDX_JSON, '"spdxVersion": "SPDX-2.3"'),
        (SBOMFormat.SPDX_TAG_VALUE, "SPDXVersion: SPDX-2.3"),
    ]:
        body, media = output_module.serialize(sbom, fmt)
        assert expected in body
        assert media in {"application/vnd.cyclonedx+json",
                          "application/spdx+json",
                          "text/spdx"}


def test_media_type_lookup():
    assert output_module.get_media_type(SBOMFormat.CYCLONEDX_JSON) == "application/vnd.cyclonedx+json"
    assert output_module.get_media_type(SBOMFormat.CYCLONEDX_XML) == "application/vnd.cyclonedx+xml"
    assert output_module.get_media_type(SBOMFormat.SPDX_TAG_VALUE) == "text/spdx"


def test_license_expression_round_trip():
    sbom = _make_sbom()
    parsed = json.loads(output_module.to_cyclonedx_json(sbom))
    exprs = [c for c in parsed["components"] if c["name"] == "requests"]
    assert exprs and exprs[0]["licenses"][0].get("expression") == "Apache-2.0"


def test_serialize_unknown_format_raises():
    from sbom_generator import output as om
    import pytest

    with pytest.raises(ValueError):
        om.serialize(_make_sbom(), "no-such-format")  # type: ignore[arg-type]
