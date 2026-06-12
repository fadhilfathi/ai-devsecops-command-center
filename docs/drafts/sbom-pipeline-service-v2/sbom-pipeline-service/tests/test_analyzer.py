"""Tests for the SBOM analyzer."""

from __future__ import annotations

import pytest

from sbom_pipeline.analyzer import _parse_size, _total_size_bytes, analyze, size_bucket
from sbom_pipeline.models import (
    Sbom,
    SbomComponent,
    SbomComponentType,
    SbomDependency,
    SbomLicense,
    SbomMetadata,
)


def _make_sbom(components=None, dependencies=None) -> Sbom:
    return Sbom(
        specVersion="1.5",
        version=1,
        metadata=SbomMetadata(timestamp="2025-01-01T00:00:00Z"),
        components=components or [],
        dependencies=dependencies or [],
    )


def test_analyze_empty_sbom():
    stats = analyze(_make_sbom())
    assert stats == {
        "components": 0,
        "transitive_depth": 0,
        "ecosystems": [],
        "license_breakdown": {},
        "total_size_bytes": 0,
    }


def test_analyze_counts_components():
    sbom = _make_sbom(
        components=[
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:a", name="a"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:b", name="b"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:c", name="c"),
        ]
    )
    stats = analyze(sbom)
    assert stats["components"] == 3


def test_analyze_ecosystems():
    sbom = _make_sbom(
        components=[
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:a",
                name="a",
                purl="pkg:npm/lodash@4",
            ),
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:b",
                name="b",
                purl="pkg:pypi/requests@2",
            ),
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:c",
                name="c",
                purl="pkg:npm/express@4",
            ),
        ]
    )
    stats = analyze(sbom)
    assert set(stats["ecosystems"]) == {"npm", "pypi"}


def test_analyze_license_breakdown():
    sbom = _make_sbom(
        components=[
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:a",
                name="a",
                licenses=[SbomLicense(license={"id": "MIT"})],
            ),
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:b",
                name="b",
                licenses=[SbomLicense(license={"id": "MIT"})],
            ),
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:c",
                name="c",
                licenses=[SbomLicense(license={"name": "Apache-2.0"})],
            ),
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:d",
                name="d",
                # No licenses at all — counts as "unknown"
            ),
        ]
    )
    stats = analyze(sbom)
    assert stats["license_breakdown"]["MIT"] == 2
    assert stats["license_breakdown"]["Apache-2.0"] == 1
    assert stats["license_breakdown"]["unknown"] == 1


def test_analyze_transitive_depth():
    # a -> b -> c
    sbom = _make_sbom(
        components=[
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:a", name="a"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:b", name="b"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:c", name="c"),
        ],
        dependencies=[
            SbomDependency(ref="urn:cdx:a", dependsOn=["urn:cdx:b"]),
            SbomDependency(ref="urn:cdx:b", dependsOn=["urn:cdx:c"]),
        ],
    )
    stats = analyze(sbom)
    assert stats["transitive_depth"] == 2


def test_analyze_transitive_depth_handles_cycles():
    sbom = _make_sbom(
        components=[
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:a", name="a"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:b", name="b"),
        ],
        dependencies=[
            SbomDependency(ref="urn:cdx:a", dependsOn=["urn:cdx:b"]),
            SbomDependency(ref="urn:cdx:b", dependsOn=["urn:cdx:a"]),
        ],
    )
    # Cycles collapse to depth 0 — we never spin.
    stats = analyze(sbom)
    assert stats["transitive_depth"] == 0


def test_analyze_transitive_depth_handles_disconnected_graph():
    # Two disjoint leaves plus a 3-deep chain on the side.
    sbom = _make_sbom(
        components=[
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:a", name="a"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:b", name="b"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:c", name="c"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:d", name="d"),
            SbomComponent(type=SbomComponentType.LIBRARY, bom_ref="urn:cdx:e", name="e"),
        ],
        dependencies=[
            SbomDependency(ref="urn:cdx:a", dependsOn=["urn:cdx:b"]),
            SbomDependency(ref="urn:cdx:b", dependsOn=["urn:cdx:c"]),
            SbomDependency(ref="urn:cdx:d", dependsOn=["urn:cdx:e"]),
        ],
    )
    stats = analyze(sbom)
    # Chain a->b->c is depth 2; chain d->e is depth 1.
    assert stats["transitive_depth"] == 2


def test_analyze_size_bytes():
    sbom = _make_sbom(
        components=[
            SbomComponent(
                type=SbomComponentType.LIBRARY,
                bom_ref="urn:cdx:a",
                name="a",
                model_config={"extra": "allow"},
            ),
        ],
    )
    # The model has no properties field, but the analyzer looks at
    # ``c.model_extra`` which is set by the ``extra="allow"`` config.
    # We set it via __init__ with extra data using Pydantic 2 syntax.
    sbom.components[0].__pydantic_extra__ = {
        "properties": [
            {"name": "size", "value": "1 mb"},
            {"name": "installSize", "value": "512 kb"},
        ]
    }
    stats = analyze(sbom)
    assert stats["total_size_bytes"] == 1024 * 1024 + 512 * 1024


# ---------------------------------------------------------------------------
# size_bucket helper
# ---------------------------------------------------------------------------


def test_size_bucket():
    assert size_bucket(0) == "small"
    assert size_bucket(99) == "small"
    assert size_bucket(100) == "medium"
    assert size_bucket(999) == "medium"
    assert size_bucket(1_000) == "large"
    assert size_bucket(9_999) == "large"
    assert size_bucket(10_000) == "xlarge"


# ---------------------------------------------------------------------------
# _parse_size helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("100", 100),
        ("1 kb", 1024),
        ("1.5 mb", int(1.5 * 1024 * 1024)),
        ("2 GB", 2 * 1024 * 1024 * 1024),
        ("not a size", 0),
        ("", 0),
    ],
)
def test_parse_size(raw, expected):
    assert _parse_size(raw) == expected
