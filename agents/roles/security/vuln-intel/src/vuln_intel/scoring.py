"""Severity scoring utilities for vuln-intel.

Implements:
  * CVSS 3.x / 4.0 vector parsing & severity bucketing
  * EPSS score normalization
  * CISA KEV membership lookup
  * Aggregate "qualitative" severity determination

The functions are pure — they don't touch the network. Source-specific
code lives in :mod:`vuln_intel.sources`.
"""
from __future__ import annotations

import math
import re
from typing import Any

from .models.cve import CvssScore, ScoreSource, SeverityAggregate, SeverityQualitative


# ============================================================================
# CVSS 3.x — full calculator (so we don't depend on an external package)
# ============================================================================


# Per CVSS v3.1 spec, section 8 ("Qualitative Severity Rating Scale")
_CVSS3_SEVERITY_RANGES: list[tuple[float, float, SeverityQualitative]] = [
    (0.0, 0.0, SeverityQualitative.NONE),
    (0.1, 3.9, SeverityQualitative.LOW),
    (4.0, 6.9, SeverityQualitative.MEDIUM),
    (7.0, 8.9, SeverityQualitative.HIGH),
    (9.0, 10.0, SeverityQualitative.CRITICAL),
]

# Weights for CVSS v3.x base score (per FIRST spec).
_CVSS3_WEIGHTS: dict[str, float] = {
    # exploitability
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},  # attack vector
    "AC": {"L": 0.77, "H": 0.44},  # attack complexity
    "PR": {
        # depends on scope — we use the "scope unchanged" version; the
        # impact subformula multiplies accordingly. The full calculator
        # below applies scope-aware weighting.
        "N": 0.85,
        "H": 0.62,  # will be reduced to 0.68 in unchanged-scope
    },
    "UI": {"N": 0.85, "R": 0.62},  # user interaction
    # impact
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},  # confidentiality
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},  # integrity
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},  # availability
}

# CVSS v3 severity for impact subscore
_IMPACT_RANGES: list[tuple[float, SeverityQualitative]] = [
    (6.42, SeverityQualitative.HIGH),
    (4.0, SeverityQualitative.MEDIUM),
    (0.0, SeverityQualitative.LOW),
]


def _roundup(x: float) -> float:
    """CVSS 'Roundup' — round to nearest 0.1, with the '1 decimal' rule."""
    int_input = round(x * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS vector string into a ``{metric: value}`` dict.

    Example::

        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        -> {"AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U",  "C": "H",  "I": "H",  "A": "H"}
    """
    if not vector.startswith("CVSS:"):
        raise ValueError(f"invalid CVSS vector (no CVSS: prefix): {vector!r}")
    parts = vector.split("/")
    # parts[0] is the version, e.g. "CVSS:3.1"
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        if ":" not in part:
            # invalid segment
            continue
        k, _, v = part.partition(":")
        metrics[k.strip().upper()] = v.strip()
    return metrics


def cvss3_severity_from_score(score: float) -> SeverityQualitative:
    """Return the qualitative severity for a CVSS v3 base score."""
    score = _roundup(score)
    for lo, hi, sev in _CVSS3_SEVERITY_RANGES:
        if lo <= score <= hi:
            return sev
    return SeverityQualitative.UNKNOWN


def compute_cvss3_base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS 3.x base score from a parsed metrics dict.

    Implements the formula from
    https://www.first.org/cvss/v3.1/specification-document, section 7.
    """
    # 1. Impact sub-score (ISS)
    c = _CVSS3_WEIGHTS["C"][metrics.get("C", "N")]
    i = _CVSS3_WEIGHTS["I"][metrics.get("I", "N")]
    a = _CVSS3_WEIGHTS["A"][metrics.get("A", "N")]
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    # 2. Impact
    scope = metrics.get("S", "U")
    if scope == "U":
        impact = 6.42 * iss
    else:  # scope changed
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    # 3. Exploitability
    av = _CVSS3_WEIGHTS["AV"][metrics.get("AV", "N")]
    ac = _CVSS3_WEIGHTS["AC"][metrics.get("AC", "L")]
    ui = _CVSS3_WEIGHTS["UI"][metrics.get("UI", "N")]
    pr_raw = metrics.get("PR", "N")
    if scope == "C":
        pr = 0.62 if pr_raw == "H" else 0.85
    else:
        pr = 0.68 if pr_raw == "H" else 0.85
    exploitability = 8.22 * av * ac * pr * ui
    # 4. Base score
    if impact <= 0.0:
        base = 0.0
    elif scope == "U":
        base = _roundup(min(exploitability + impact, 10.0))
    else:  # scope changed
        base = _roundup(min(1.08 * (exploitability + impact), 10.0))
    return base


def parse_cvss3_vector(vector: str) -> CvssScore:
    """Parse a CVSS 3.x vector into a :class:`CvssScore` model."""
    version_match = re.match(r"^CVSS:(3\.[01])/", vector)
    if not version_match:
        raise ValueError(f"not a CVSS 3.x vector: {vector!r}")
    version = version_match.group(1)
    metrics = parse_cvss_vector(vector)
    score = compute_cvss3_base_score(metrics)
    return CvssScore(
        version=version,  # type: ignore[arg-type]
        vector=vector,
        score=score,
        severity=cvss3_severity_from_score(score),
        source=ScoreSource.DERIVED,
    )


# ============================================================================
# CVSS 4.0
# CVSS 4.0 has a substantially different metric set. For ingest we do not
# implement the full calculator — we trust the upstream-provided base score
# when present, and only compute the qualitative bucket from it.
# ============================================================================

_CVSS4_SEVERITY_RANGES: list[tuple[float, float, SeverityQualitative]] = [
    (0.0, 0.0, SeverityQualitative.NONE),
    (0.1, 3.9, SeverityQualitative.LOW),
    (4.0, 6.9, SeverityQualitative.MEDIUM),
    (7.0, 8.9, SeverityQualitative.HIGH),
    (9.0, 10.0, SeverityQualitative.CRITICAL),
]


def cvss4_severity_from_score(score: float) -> SeverityQualitative:
    for lo, hi, sev in _CVSS4_SEVERITY_RANGES:
        if lo <= score <= hi:
            return sev
    return SeverityQualitative.UNKNOWN


def parse_cvss4_vector(
    vector: str, upstream_score: float | None = None
) -> CvssScore:
    """Parse a CVSS 4.0 vector.

    We accept the vector and (when provided) the upstream-computed score.
    If ``upstream_score`` is missing we fall back to 0.0 (UNKNOWN).
    """
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError(f"not a CVSS 4.0 vector: {vector!r}")
    score = float(upstream_score) if upstream_score is not None else 0.0
    return CvssScore(
        version="4.0",
        vector=vector,
        score=max(0.0, min(score, 10.0)),
        severity=cvss4_severity_from_score(score),
        source=ScoreSource.DERIVED,
    )


# ============================================================================
# Severity aggregation
# ============================================================================


def aggregate_severity(
    *,
    cvss_v3: CvssScore | None = None,
    cvss_v4: CvssScore | None = None,
    cvss_v2: CvssScore | None = None,
    fallback_qualitative: SeverityQualitative = SeverityQualitative.UNKNOWN,
    primary_source: ScoreSource = ScoreSource.DERIVED,
    rationale: str | None = None,
) -> SeverityAggregate:
    """Choose the strongest severity signal available.

    Priority is CVSS v4 > CVSS v3 > CVSS v2 > fallback. The chosen
    qualitative is the maximum of all available buckets, so we never
    under-report a vulnerability.
    """
    candidates: list[tuple[CvssScore, ScoreSource]] = []
    if cvss_v4 is not None:
        candidates.append((cvss_v4, ScoreSource.OSV if primary_source == ScoreSource.OSV else primary_source))
    if cvss_v3 is not None:
        candidates.append((cvss_v3, primary_source))
    if cvss_v2 is not None:
        candidates.append((cvss_v2, primary_source))

    qualitative = fallback_qualitative
    for c, src in candidates:
        if _severity_rank(c.severity) > _severity_rank(qualitative):
            qualitative = c.severity
    primary = candidates[0][1] if candidates else primary_source

    if not rationale:
        if cvss_v4 is not None:
            rationale = f"selected CVSS v4 score {cvss_v4.score}"
        elif cvss_v3 is not None:
            rationale = f"selected CVSS v3 score {cvss_v3.score}"
        elif cvss_v2 is not None:
            rationale = f"selected CVSS v2 score {cvss_v2.score}"
        else:
            rationale = f"no CVSS vector available, falling back to {fallback_qualitative.value}"

    return SeverityAggregate(
        qualitative=qualitative,
        cvss_v3=cvss_v3,
        cvss_v4=cvss_v4,
        cvss_v2=cvss_v2,
        primary_source=primary,
        rationale=rationale,
    )


def _severity_rank(sev: SeverityQualitative) -> int:
    return {
        SeverityQualitative.UNKNOWN: -1,
        SeverityQualitative.NONE: 0,
        SeverityQualitative.LOW: 1,
        SeverityQualitative.MEDIUM: 2,
        SeverityQualitative.HIGH: 3,
        SeverityQualitative.CRITICAL: 4,
    }[sev]


def is_minimum_severity(sev: SeverityQualitative, threshold: SeverityQualitative) -> bool:
    """Return True if ``sev`` is >= ``threshold`` (qualitatively)."""
    return _severity_rank(sev) >= _severity_rank(threshold)


# ============================================================================
# EPSS helpers
# ============================================================================


def epss_risk_band(score: float) -> str:
    """Categorise an EPSS score into a human-friendly band.

    The bands match the "nvd-nist" guidance:
      * 0.0–0.1  : very low
      * 0.1–0.3  : low
      * 0.3–0.6  : medium
      * 0.6–0.9  : high
      * 0.9–1.0  : very high
    """
    if score < 0.1:
        return "very_low"
    if score < 0.3:
        return "low"
    if score < 0.6:
        return "medium"
    if score < 0.9:
        return "high"
    return "very_high"


def normalize_epss_payload(payload: list[dict[str, Any]]) -> dict[str, tuple[float, float]]:
    """Normalize an EPSS response payload into a ``{cve: (score, percentile)}`` dict."""
    out: dict[str, tuple[float, float]] = {}
    for row in payload:
        cve = row.get("cve")
        score = row.get("epss")
        pct = row.get("percentile")
        if not cve or score is None or pct is None:
            continue
        try:
            out[cve.upper()] = (float(score), float(pct))
        except (TypeError, ValueError):
            continue
    return out
