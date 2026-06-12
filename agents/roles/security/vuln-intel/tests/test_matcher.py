"""Tests for the SBOM matcher."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.matcher import match_components, version_in_range
from vuln_intel.models.cve import (
    AffectedPackage,
    AffectedVersionRange,
    CveRecord,
    CvssScore,
    ScoreSource,
    SeverityAggregate,
    SeverityQualitative,
    SourceName,
)
from vuln_intel.models.dto import MatchRequestComponent


def _vuln(name: str, ecosystem: str, purl: str, versions: list[AffectedVersionRange]) -> CveRecord:
    return CveRecord(
        id="CVE-2024-99999",
        source=[SourceName.OSV],
        summary="x",
        severity=SeverityAggregate(
            qualitative=SeverityQualitative.HIGH,
            cvss_v3=CvssScore(version="3.1", vector="x", score=7.5, severity=SeverityQualitative.HIGH, source=ScoreSource.NVD_PRIMARY),
            primary_source=ScoreSource.OSV,
        ),
        affected=[AffectedPackage(name=name, ecosystem=ecosystem, purl=purl, versions=versions)],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


def test_version_in_range_semver() -> None:
    ranges = [AffectedVersionRange(introduced="1.0.0", fixed="1.2.4")]
    assert version_in_range("1.0.0", ranges)
    assert version_in_range("1.2.3", ranges)
    assert not version_in_range("1.2.4", ranges)
    assert not version_in_range("0.9.9", ranges)


def test_match_by_purl_with_version() -> None:
    vuln = _vuln(
        "foo", "PyPI", "pkg:pypi/foo@1.0.0", [AffectedVersionRange(introduced="0", fixed="1.2.4")]
    )
    comp = MatchRequestComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    findings = match_components([comp], [vuln])
    assert len(findings) == 1
    assert findings[0].affected is True
    assert findings[0].confidence > 0.5


def test_match_no_version_lower_confidence() -> None:
    vuln = _vuln(
        "foo", "PyPI", "pkg:pypi/foo@1.0.0", [AffectedVersionRange(introduced="0", fixed="1.2.4")]
    )
    comp = MatchRequestComponent(name="foo", ecosystem="PyPI")
    findings = match_components([comp], [vuln])
    assert len(findings) == 1
    assert findings[0].confidence < 0.8


def test_match_filtered_by_severity() -> None:
    vuln = _vuln(
        "foo", "PyPI", "pkg:pypi/foo@1.0.0", [AffectedVersionRange(introduced="0", fixed="1.2.4")]
    )
    comp = MatchRequestComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    findings = match_components([comp], [vuln], min_severity=SeverityQualitative.CRITICAL)
    assert findings == []


def test_match_exploited_only() -> None:
    vuln = _vuln(
        "foo", "PyPI", "pkg:pypi/foo@1.0.0", [AffectedVersionRange(introduced="0", fixed="1.2.4")]
    )
    comp = MatchRequestComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    findings = match_components([comp], [vuln], exploited_only=True)
    # no kev/epss set
    assert findings == []


def test_match_no_double_counting() -> None:
    vuln = _vuln(
        "foo", "PyPI", "pkg:pypi/foo@1.0.0", [AffectedVersionRange(introduced="0", fixed="1.2.4")]
    )
    comp = MatchRequestComponent(purl="pkg:pypi/foo@1.0.0", name="foo", version="1.0.0")
    findings = match_components([comp], [vuln])
    assert len(findings) == 1
