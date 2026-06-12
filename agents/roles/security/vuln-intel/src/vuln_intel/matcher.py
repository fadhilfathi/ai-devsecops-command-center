"""SBOM ↔ CVE matching.

The matcher joins a list of components (PURL / name+ecosystem) against the
vulnerability database. The output is one :class:`MatchFinding` per
(component, vulnerability) pair, with a confidence score.

Version-range matching uses the same OSV semantics as the rest of the
service: ``introduced`` is inclusive, ``fixed`` is exclusive. The matcher
implements a *naive* SemVer comparator — good enough for most package
managers (npm, PyPI, Maven, Go, crates.io, RubyGems). For ecosystems
with non-semver versions (e.g. Debian, Alpine) we degrade to a string
comparison and lower the confidence.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .models.cve import (
    AffectedPackage,
    AffectedVersionRange,
    CveRecord,
    MatchFinding,
    MatchRequestComponent,
    SeverityQualitative,
)
from .scoring import is_minimum_severity

logger = logging.getLogger(__name__)


_SEMVER_RE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:[-+](?P<suffix>[\w.\-]+))?$"
)


@dataclass(frozen=True)
class VersionTriple:
    major: int
    minor: int
    patch: int
    suffix: str = ""  # lexically-ordered suffix, e.g. "-rc.1", "+build.42"

    @classmethod
    def parse(cls, v: str) -> "VersionTriple | None":
        m = _SEMVER_RE.match(v)
        if not m:
            return None
        return cls(
            major=int(m["major"]),
            minor=int(m["minor"]),
            patch=int(m["patch"]),
            suffix=m["suffix"] or "",
        )

    def __lt__(self, other: "VersionTriple") -> bool:  # type: ignore[override]
        return (self.major, self.minor, self.patch, self.suffix) < (
            other.major,
            other.minor,
            other.patch,
            other.suffix,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VersionTriple):
            return False
        return (self.major, self.minor, self.patch, self.suffix) == (
            other.major,
            other.minor,
            other.patch,
            other.suffix,
        )

    def __le__(self, other: "VersionTriple") -> bool:  # type: ignore[override]
        return self < other or self == other


def version_in_range(version: str, ranges: Iterable[AffectedVersionRange]) -> bool:
    """Test whether ``version`` falls inside any of the ``ranges``."""
    v = VersionTriple.parse(version)
    if v is None:
        # Non-semver — try a string comparison
        return _string_in_range(version, ranges)
    for r in ranges:
        lo = VersionTriple.parse(r.introduced) if r.introduced else None
        hi_excl = VersionTriple.parse(r.fixed) if r.fixed else None
        hi_incl = VersionTriple.parse(r.last_affected) if r.last_affected else None
        if lo is not None and v < lo:
            continue
        if hi_excl is not None and v >= hi_excl:
            continue
        if hi_incl is not None and v > hi_incl:
            continue
        return True
    return False


def _string_in_range(version: str, ranges: Iterable[AffectedVersionRange]) -> bool:
    for r in ranges:
        if r.introduced and version < r.introduced:
            continue
        if r.fixed and version >= r.fixed:
            continue
        if r.last_affected and version > r.last_affected:
            continue
        return True
    return False


def _package_matches(comp: MatchRequestComponent, ap: AffectedPackage) -> bool:
    """Best-effort package-level match (no version)."""
    if comp.purl and ap.purl:
        return comp.purl.lower() == ap.purl.lower()
    if comp.purl and ap.name:
        # Purl encodes the name+ecosystem already
        return comp.purl.lower().startswith("pkg:") and comp.name.lower() == ap.name.lower()
    if comp.ecosystem and ap.ecosystem and comp.ecosystem.lower() != ap.ecosystem.lower():
        return False
    return comp.name.lower() == ap.name.lower()


def match_components(
    components: list[MatchRequestComponent],
    records: Iterable[CveRecord],
    *,
    min_severity: SeverityQualitative = SeverityQualitative.UNKNOWN,
    exploited_only: bool = False,
) -> list[MatchFinding]:
    """Match a list of components against a set of vulnerability records."""
    findings: list[MatchFinding] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        if exploited_only and not rec.is_exploited:
            continue
        if not is_minimum_severity(rec.severity.qualitative, min_severity):
            continue
        for ap in rec.affected:
            for comp in components:
                if not _package_matches(comp, ap):
                    continue
                # Decide whether the component version is affected
                if comp.version:
                    affected = version_in_range(comp.version, ap.versions)
                    if not affected:
                        continue
                else:
                    # No version known — match the package by name only,
                    # low confidence.
                    affected = True
                key = (comp.name.lower(), rec.id)
                if key in seen:
                    continue
                seen.add(key)
                confidence = _confidence(comp, ap, rec)
                findings.append(
                    MatchFinding(
                        component=comp,
                        cve=rec,
                        affected=affected,
                        confidence=confidence,
                        notes=(
                            f"matched by {('purl' if comp.purl else 'name+ecosystem')}"
                            f" — qualitative={rec.severity.qualitative.value}, "
                            f"kev={bool(rec.kev and rec.kev.exploited)}, "
                            f"epss={(rec.epss.score if rec.epss else None)}"
                        ),
                    )
                )
    return findings


def _confidence(comp: MatchRequestComponent, ap: AffectedPackage, rec: CveRecord) -> float:
    score = 0.5
    if comp.purl and ap.purl and comp.purl == ap.purl:
        score += 0.25
    if comp.version:
        score += 0.15
    if rec.severity.cvss_v3 or rec.severity.cvss_v4:
        score += 0.05
    if rec.kev and rec.kev.exploited:
        score += 0.05
    return min(score, 1.0)


def filter_findings(
    findings: list[MatchFinding], *, min_severity: SeverityQualitative, exploited_only: bool
) -> list[MatchFinding]:
    out = findings
    if exploited_only:
        out = [f for f in out if f.cve.is_exploited]
    out = [f for f in out if is_minimum_severity(f.cve.severity.qualitative, min_severity)]
    return out


def summarise(findings: list[MatchFinding]) -> dict[SeverityQualitative, int]:
    from collections import Counter

    counts: Counter[SeverityQualitative] = Counter()
    for f in findings:
        counts[f.cve.severity.qualitative] += 1
    return dict(counts)


def timestamp() -> datetime:
    return datetime.utcnow()
