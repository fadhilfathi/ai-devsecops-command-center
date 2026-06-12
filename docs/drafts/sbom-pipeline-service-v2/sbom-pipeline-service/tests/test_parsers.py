"""Tests for the CycloneDX and SPDX normalizers."""

from __future__ import annotations

import json

import pytest

from sbom_pipeline.models import (
    SBOMFormat,
    Sbom,
    SbomComponent,
    SbomComponentType,
    SbomHash,
    SbomLicense,
    SbomMetadata,
    SbomTool,
    ecosystem_from_purl,
    mint_bom_ref,
    sha256_text,
)
from sbom_pipeline.parsers import (
    cyclonedx_text_to_sbom,
    serialize_sbom,
    syft_to_cyclonedx,
    syft_to_spdx_dict,
)


# ---------------------------------------------------------------------------
# mint_bom_ref
# ---------------------------------------------------------------------------


def test_mint_bom_ref_uses_purl_when_available():
    a = mint_bom_ref("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    b = mint_bom_ref("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    assert a == b  # deterministic
    assert a.startswith("urn:cdx:")
    assert len(a) == len("urn:cdx:") + 16


def test_mint_bom_ref_falls_back_to_name_version():
    a = mint_bom_ref("lodash", "4.17.21")
    b = mint_bom_ref("lodash", "4.17.21")
    assert a == b
    assert a.startswith("urn:cdx:")


def test_mint_bom_ref_differs_by_purl_vs_no_purl():
    a = mint_bom_ref("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    b = mint_bom_ref("lodash", "4.17.21")
    # Different materials => different bom-ref.
    assert a != b


def test_mint_bom_ref_differs_by_version():
    a = mint_bom_ref("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    b = mint_bom_ref("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")
    assert a != b


# ---------------------------------------------------------------------------
# syft_to_cyclonedx
# ---------------------------------------------------------------------------


def test_syft_to_cyclonedx_produces_canonical_wire_shape(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    assert isinstance(sbom, Sbom)
    assert sbom.bomFormat == "CycloneDX"
    assert sbom.specVersion == "1.5"
    assert sbom.version == 1
    assert sbom.metadata is not None
    assert sbom.metadata.timestamp
    assert sbom.metadata.tools
    assert sbom.metadata.tools[0].name == "syft"


def test_syft_to_cyclonedx_component_count_matches_artifacts(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    raw_count = len(sample_syft_payload.get("artifacts") or [])
    assert len(sbom.components) == raw_count


def test_syft_to_cyclonedx_dedupes_components_by_bom_ref():
    # Two artifacts that hash to the same bom-ref.
    raw = {
        "artifacts": [
            {"name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"},
            {"name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"},
        ]
    }
    sbom = syft_to_cyclonedx(raw)
    assert len(sbom.components) == 1


def test_syft_to_cyclonedx_uses_canonical_bom_ref(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    refs = {c.bom_ref for c in sbom.components}
    assert all(r.startswith("urn:cdx:") for r in refs)


def test_syft_to_cyclonedx_assigns_library_type_to_default(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    for c in sbom.components:
        assert c.type in {
            SbomComponentType.LIBRARY,
            SbomComponentType.APPLICATION,
            SbomComponentType.OPERATING_SYSTEM,
            SbomComponentType.CONTAINER,
        }


def test_syft_to_cyclonedx_preserves_licenses(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    lodash = next((c for c in sbom.components if c.name == "lodash"), None)
    assert lodash is not None
    assert lodash.licenses
    # The first license should be a license object.
    assert lodash.licenses[0].license or lodash.licenses[0].expression


def test_syft_to_cyclonedx_preserves_hashes(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    lodash = next((c for c in sbom.components if c.name == "lodash"), None)
    assert lodash is not None
    assert lodash.hashes


def test_syft_to_cyclonedx_handles_empty():
    sbom = syft_to_cyclonedx({})
    assert sbom.components == []


# ---------------------------------------------------------------------------
# SPDX conversion
# ---------------------------------------------------------------------------


def test_syft_to_spdx_dict_has_required_fields(sample_syft_payload):
    spdx = syft_to_spdx_dict(sample_syft_payload)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert isinstance(spdx["packages"], list)
    assert len(spdx["packages"]) == len(sample_syft_payload["artifacts"])


def test_syft_to_spdx_dict_package_has_purl_in_external_refs(sample_syft_payload):
    spdx = syft_to_spdx_dict(sample_syft_payload)
    for pkg in spdx["packages"]:
        if pkg["name"] == "lodash":
            ext_refs = pkg["externalRefs"]
            assert any(
                r["referenceType"] == "purl" and "lodash" in r["referenceLocator"]
                for r in ext_refs
            )
            break
    else:
        pytest.fail("expected a lodash package in SPDX output")


def test_syft_to_spdx_dict_uses_noassertion_for_download_location(sample_syft_payload):
    spdx = syft_to_spdx_dict(sample_syft_payload)
    for pkg in spdx["packages"]:
        assert pkg["downloadLocation"] == "NOASSERTION"


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_cyclonedx_text_to_sbom_round_trip(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    text, media = serialize_sbom(sbom, SBOMFormat.CYCLONEDX_JSON)
    reparsed = cyclonedx_text_to_sbom(text)
    assert reparsed.bomFormat == "CycloneDX"
    assert len(reparsed.components) == len(sbom.components)
    # bom-ref is stable across the round-trip.
    assert {c.bom_ref for c in reparsed.components} == {c.bom_ref for c in sbom.components}


def test_serialize_cyclonedx_json_emits_kebab_bom_ref(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    text, _ = serialize_sbom(sbom, SBOMFormat.CYCLONEDX_JSON)
    assert '"bom-ref"' in text  # kebab-case wire key
    assert '"bomFormat"' in text


def test_serialize_cyclonedx_xml_is_well_formed_xml(sample_syft_payload):
    from xml.etree import ElementTree as ET
    sbom = syft_to_cyclonedx(sample_syft_payload)
    body, media = serialize_sbom(sbom, SBOMFormat.CYCLONEDX_XML)
    assert media == "application/vnd.cyclonedx+xml"
    root = ET.fromstring(body)
    assert root.tag.endswith("bom")


def test_serialize_spdx_tag_value_contains_package_entries(sample_syft_payload):
    sbom = syft_to_cyclonedx(sample_syft_payload)
    body, media = serialize_sbom(sbom, SBOMFormat.SPDX_TAG_VALUE)
    assert media == "text/spdx"
    assert "SPDXVersion: SPDX-2.3" in body
    assert "PackageName: lodash" in body
