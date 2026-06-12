"""Unit tests for the unified CveRecord merge logic and severity aggregation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vuln_intel.models.cve import (
    CveRecord,
    CvssScore,
    Reference,
    SeverityAggregate,
    SeverityQualitative,
    SourceName,
)
from vuln_intel.scoring import (
    aggregate_severity,
    compute_cvss3_base_score,
    cvss3_severity_from_score,
    parse_cvss3_vector,
    parse_cvss_vector,
)


def _base_record(severity: SeverityQualitative = SeverityQualitative.HIGH) -> CveRecord:
    return CveRecord(
        id="CVE-2024-31337",
        aliases=["GHSA-xxxx-yyyy-zzzz"],
        source=[SourceName.NVD],
        published=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2024, 1, 2, tzinfo=timezone.utc),
        summary="Test CVE",
        details="Some details",
        severity=SeverityAggregate(
            qualitative=severity,
            primary_source="nvd:primary",
        ),
        affected=[],
        references=[Reference(url="https://example.com/advisory", tags=["vendor-advisory"])],
        cwes=[],
    )


def test_merge_picks_higher_severity() -> None:
    a = _base_record(severity=SeverityQualitative.MEDIUM)
    b = _base_record(severity=SeverityQualitative.CRITICAL)
    merged = a.merge(b)
    assert merged.severity.qualitative == SeverityQualitative.CRITICAL
    assert merged.aliases == ["GHSA-xxxx-yyyy-zzzz"]


def test_merge_unions_references() -> None:
    a = _base_record()
    b = _base_record()
    b.references = [Reference(url="https://example.com/extra")]
    a.merge(b)
    urls = sorted(r.url for r in a.references)
    assert urls == ["https://example.com/advisory", "https://example.com/extra"]


def test_merge_unions_aliases() -> None:
    a = _base_record()
    b = _base_record()
    b.aliases = ["PYSEC-2024-100"]
    a.merge(b)
    assert set(a.aliases) == {"GHSA-xxxx-yyyy-zzzz", "PYSEC-2024-100"}


def test_merge_preserves_earlier_published() -> None:
    a = _base_record()
    a.published = datetime(2024, 1, 5, tzinfo=timezone.utc)
    b = _base_record()
    b.published = datetime(2024, 1, 1, tzinfo=timezone.utc)
    a.merge(b)
    assert a.published == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_parse_cvss_vector() -> None:
    v = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert v == {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
    }


@pytest.mark.parametrize(
    "vector,expected_score,expected_sev",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, SeverityQualitative.CRITICAL),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.3, SeverityQualitative.LOW),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5, SeverityQualitative.MEDIUM),
    ],
)
def test_compute_cvss3_base_score(vector: str, expected_score: float, expected_sev: SeverityQualitative) -> None:
    metrics = parse_cvss_vector(vector)
    score = compute_cvss3_base_score(metrics)
    assert score == pytest.approx(expected_score, abs=0.1)
    assert cvss3_severity_from_score(score) == expected_sev


def test_parse_cvss3_vector_returns_cvss_score() -> None:
    cs = parse_cvss3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert isinstance(cs, CvssScore)
    assert cs.version == "3.1"
    assert cs.severity == SeverityQualitative.CRITICAL


def test_aggregate_severity_prefers_v4() -> None:
    sev = aggregate_severity(
        cvss_v3=CvssScore(version="3.1", vector="CVSS:3.1/AV:N", score=7.5, severity=SeverityQualitative.HIGH, source="nvd:primary"),
        cvss_v4=CvssScore(version="4.0", vector="CVSS:4.0/AV:N", score=8.5, severity=SeverityQualitative.HIGH, source="nvd:primary"),
    )
    assert sev.cvss_v4 is not None
    assert sev.cvss_v3 is not None
    assert sev.qualitative == SeverityQualitative.HIGH
