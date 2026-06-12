"""Tests for the internal SBOM model and Syft normalizer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from sbom_generator.models.sbom import (
    Component,
    ComponentType,
    SBOM,
    SBOMFormat,
    fingerprint,
    is_valid_cpe,
    is_valid_purl,
    normalize_syft_output,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_is_valid_purl():
    assert is_valid_purl("pkg:npm/lodash@4.17.21")
    assert is_valid_purl("pkg:pypi/requests@2.31.0")
    assert not is_valid_purl("not-a-purl")
    assert not is_valid_purl(None)
    assert not is_valid_purl("")


def test_is_valid_cpe():
    assert is_valid_cpe("cpe:2.3:a:apache:httpd:2.4.57:*:*:*:*:*:*:*")
    assert is_valid_cpe("cpe:2.2:a:vendor:product:1.0:*:*:*:*:*:*:*")
    assert not is_valid_cpe("not-a-cpe")
    assert not is_valid_cpe(None)


def test_fingerprint_stable():
    c = Component(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")
    assert fingerprint(c) == fingerprint(c)
    d = Component(name="lodash", version="4.17.21")
    assert fingerprint(c) != fingerprint(d)


def test_fingerprint_distinguishes_name_and_version():
    a = Component(name="a", version="1.0.0")
    b = Component(name="a", version="1.0.1")
    c = Component(name="b", version="1.0.0")
    assert len({fingerprint(a), fingerprint(b), fingerprint(c)}) == 3


def test_normalize_syft_output_extracts_components(sample_syft_payload):
    sbom = normalize_syft_output(sample_syft_payload)
    assert isinstance(sbom, SBOM)
    assert sbom.format == SBOMFormat.SYFT_JSON
    assert len(sbom.components) >= 3
    names = {c.name for c in sbom.components}
    assert "lodash" in names or any("lodash" in (n or "") for n in names)


def test_normalize_syft_output_extracts_licenses(sample_syft_payload):
    sbom = normalize_syft_output(sample_syft_payload)
    licensed = [c for c in sbom.components if c.licenses]
    assert licensed, "expected at least one component with a license"


def test_normalize_syft_output_extracts_hashes(sample_syft_payload):
    sbom = normalize_syft_output(sample_syft_payload)
    hashed = [c for c in sbom.components if c.hashes]
    assert hashed, "expected at least one component with a hash"


def test_normalize_syft_output_records_metadata(sample_syft_payload):
    sbom = normalize_syft_output(sample_syft_payload)
    assert sbom.metadata.tools, "expected at least one tool in metadata"
    assert sbom.metadata.tools[0].name == "syft"


def test_normalize_handles_empty_payload():
    sbom = normalize_syft_output({})
    assert sbom.components == []
    assert sbom.dependencies == {}


def test_normalize_skips_artifacts_without_name_and_version():
    payload = {"artifacts": [{"name": "", "version": ""}, {"purl": "pkg:npm/x@1"}]}
    sbom = normalize_syft_output(payload)
    # The empty artifact is skipped. The second has no name, so it's
    # also skipped. This guards against garbage from unfinished scans.
    assert sbom.components == []


def test_component_default_type():
    c = Component(name="x")
    assert c.type == ComponentType.LIBRARY


def test_component_bom_ref_is_uuid():
    c = Component(name="x")
    other = Component(name="y")
    assert c.bom_ref != other.bom_ref
    import uuid

    uuid.UUID(c.bom_ref)
