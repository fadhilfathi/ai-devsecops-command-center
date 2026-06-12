"""S2.8 hardening — cross-source consensus tests (CF-06..CF-07).

A CVE is eligible for HIGH/CRITICAL scoring only when at least two of
{NVD, GHSA, OSV} corroborate it. Single-source HIGH/CRITICAL
classifications are tagged ``unofficial`` so the Security UI can flag
them for human review and the risk engine can down-weight them.
"""
from __future__ import annotations

import pytest

from vuln_intel.consensus import (
    CONSENSUS_SOURCES,
    MIN_SOURCES_FOR_HIGH_CRITICAL,
    CrossSourceConsensus,
    consensus_tag,
)


# ---------------------------------------------------------------------------
# CF-06: HIGH/CRITICAL with >=2 sources is NOT unofficial
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity,sources",
    [
        ("HIGH", {"nvd", "ghsa"}),
        ("CRITICAL", {"nvd", "osv"}),
        ("HIGH", {"nvd", "ghsa", "osv"}),
        ("CRITICAL", {"ghsa", "osv"}),
        ("CRITICAL", {"NVD", "GHSA"}),  # case-insensitive
    ],
)
def test_cf_06_high_critical_with_consensus_not_unofficial(severity, sources) -> None:
    cs = CrossSourceConsensus()
    d = cs.evaluate(sources, severity, cve_id="CVE-2024-0001")
    assert d.is_high_or_critical is True
    assert d.is_unofficial is False
    assert d.reason == "consensus_ok"
    # sources are normalised to lowercase
    assert all(s == s.lower() for s in d.sources)


# ---------------------------------------------------------------------------
# CF-07: single-source HIGH/CRITICAL is unofficial
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity,sources",
    [
        ("HIGH", {"nvd"}),
        ("CRITICAL", {"ghsa"}),
        ("CRITICAL", {"osv"}),
        ("HIGH", set()),  # no sources at all
    ],
)
def test_cf_07_single_source_high_critical_is_unofficial(severity, sources) -> None:
    cs = CrossSourceConsensus()
    d = cs.evaluate(sources, severity, cve_id="CVE-2024-0002")
    assert d.is_high_or_critical is True
    assert d.is_unofficial is True
    assert d.reason == "single_source_high_critical"


# ---------------------------------------------------------------------------
# Below-HIGH severities never flagged unofficial
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity,sources",
    [
        ("LOW", {"nvd"}),
        ("MEDIUM", {"ghsa"}),
        ("NONE", set()),
        ("LOW", {"nvd", "ghsa"}),
    ],
)
def test_below_high_never_unofficial(severity, sources) -> None:
    cs = CrossSourceConsensus()
    d = cs.evaluate(sources, severity)
    assert d.is_high_or_critical is False
    assert d.is_unofficial is False
    assert d.reason == "below_high"


# ---------------------------------------------------------------------------
# Unknown source names are ignored (not counted toward consensus)
# ---------------------------------------------------------------------------
def test_unknown_sources_ignored() -> None:
    cs = CrossSourceConsensus()
    d = cs.evaluate({"nvd", "epss", "kev", "qualys"}, "CRITICAL")
    # Only "nvd" is in CONSENSUS_SOURCES, so the CVE is single-source.
    assert d.source_count == 1
    assert d.is_unofficial is True
    assert d.sources == ("nvd",)


# ---------------------------------------------------------------------------
# consensus_tag helper
# ---------------------------------------------------------------------------
def test_consensus_tag_adds_unofficial() -> None:
    d = CrossSourceConsensus().evaluate({"nvd"}, "CRITICAL")
    tags = consensus_tag([], d)
    assert "unofficial" in tags


def test_consensus_tag_removes_unofficial_after_consensus() -> None:
    cs = CrossSourceConsensus()
    bad = cs.evaluate({"nvd"}, "CRITICAL")
    good = cs.evaluate({"nvd", "ghsa"}, "CRITICAL")
    tags = consensus_tag(consensus_tag([], bad), good)
    assert "unofficial" not in tags
    assert "corroborated" in tags


def test_consensus_tag_idempotent() -> None:
    d = CrossSourceConsensus().evaluate({"nvd"}, "CRITICAL")
    once = consensus_tag([], d)
    twice = consensus_tag(once, d)
    assert once == twice


# ---------------------------------------------------------------------------
# Decision dataclass carries the cve id
# ---------------------------------------------------------------------------
def test_decision_carries_cve_id() -> None:
    d = CrossSourceConsensus().evaluate({"nvd", "ghsa"}, "HIGH", cve_id="CVE-2024-9999")
    assert d.cve_id == "CVE-2024-9999"


# ---------------------------------------------------------------------------
# Module constants are stable
# ---------------------------------------------------------------------------
def test_constants() -> None:
    assert CONSENSUS_SOURCES == frozenset({"nvd", "ghsa", "osv"})
    assert MIN_SOURCES_FOR_HIGH_CRITICAL == 2
