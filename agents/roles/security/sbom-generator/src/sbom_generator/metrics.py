"""S2.7-locked SBOM pipeline metrics.

This module is the **single source of truth** for the Prometheus
metric names, label sets, and bucket boundaries used by the SBOM
generator. SREEngineer locked these in
``docs/observability/metrics-spec.md`` v1.0.0 and the
``slos-security-stack.md`` v1.2 (PlatformArchitect sign-off,
2026-06-12).

Cardinality budget
==================

We cap the total unique label combinations at the 50k soft cap set
in the SLO doc. The current per-service total is ~78,000 — over
budget, accepted for Sprint 2 (see metrics-spec §3.1). The overage
is in the ``repo_shape`` label which is only emitted when
``target_type="repo"``, so the runtime cardinality is actually
~22,000 for non-repo scans and ~78,000 worst-case for repo scans.

Locked metric set
=================

* ``devsecops_sbom_generation_duration_seconds`` — Histogram, labels
  ``{source_type, result, ecosystem, target_type, repo_shape}``.
  ``format`` is DEFERRED to Sprint 3 (4× cardinality jump — see
  metrics-spec §3.1).
* ``devsecops_sbom_components_total`` — Counter, label
  ``{sbom_size_bucket}`` with **five** buckets (D7 LOCKED, Sprint 2.7
  round 6 closure 2026-06-12): xs / small / medium / large / xlarge.
  The ``xxlarge`` bucket from the round-5 scheme was RETIRED —
  workloads that would have been xxlarge now flow into xlarge and
  are accepted as SLO overshoots. The new ``xs`` bucket catches
  trivially-small SBOMs (sub-10 components).
* ``devsecops_sbom_active_scans`` — Gauge, label ``{scanner_type}``.
* ``devsecops_sbom_scan_failures_total`` — Counter, label ``{reason}``
  with bounded reasons: ``syft_not_found`` / ``syft_timeout`` /
  ``syft_nonzero_exit`` / ``source_not_found`` / ``auth_denied`` /
  ``internal_error``.

Bucket boundaries
=================

The component-count buckets are D7 LOCKED (Sprint 2.7 round 6 closure,
2026-06-12). The scheme is the SAME across all metrics that carry the
``sbom_size_bucket`` label, in particular:

* ``devsecops_sbom_components_total`` (this module, sbom-generator :4007)
* ``devsecops_risk_calculation_duration_seconds`` (dependency-intel :4009,
  consumed by ``infra/observability/prometheus/alert-rules.yml`` for the
  5 ``RiskCalcHighLatency*`` alerts + the per-bucket SLO targets in
  ``docs/observability/slos-security-stack.md`` §3)

Locking the bucket boundaries across metrics is what makes the
``RiskCalcHighLatencyXs`` alert work — the alert queries
``sbom_size_bucket="xs"`` on the ``dependency-intel`` histogram, and the
sbom-generator's component counter must agree on the same bucket name
for the per-bucket dashboard panel to be self-consistent.

Locked boundaries:

* ``xs``      — ``n < 10``
* ``small``   — ``10 ≤ n < 100``
* ``medium``  — ``100 ≤ n < 1_000``
* ``large``   — ``1_000 ≤ n < 5_000``
* ``xlarge``  — ``n ≥ 5_000`` (no upper bound; ``xxlarge`` is RETIRED)

The ``xxlarge`` bucket from the round-5 scheme was retired on 2026-06-12
because the S2.8 cap (~5k components) blocks upstream SBOMs from
reaching ≥10k in normal operation. ≥10k workloads are treated as
``xlarge`` SLO overshoots and may be acceptable per
``docs/observability/slos-security-stack.md`` §3.

Ecosystem enum
==============

The full PlatformArchitect enum (with the ``unknown`` fallback
added per our ask):

    npm, pypi, maven, nuget, go, cargo, rubygems, composer,
    conan, apk, deb, rpm, generic, unknown
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class Ecosystem(str, Enum):
    """PlatformArchitect-locked ecosystem enum (14 values)."""

    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    GO = "go"
    CARGO = "cargo"
    RUBYGEMS = "rubygems"
    COMPOSER = "composer"
    CONAN = "conan"
    APK = "apk"
    DEB = "deb"
    RPM = "rpm"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Locked source_type label set."""

    SYFT = "syft"
    DEPENDENCY_TRACK = "dependency_track"
    IMPORT = "import"
    MANUAL = "manual"


class Result(str, Enum):
    """Locked result label set."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TargetType(str, Enum):
    """Per-source target type — drives the repo_shape label gate."""

    DOCKER = "docker"
    GIT = "git"
    DIRECTORY = "directory"
    FILE = "file"
    LOCKFILE = "lockfile"
    ARCHIVE = "archive"
    REGISTRY = "registry"
    OCI_IMAGE = "oci-image"


class FailureReason(str, Enum):
    """Bounded failure-reason vocabulary for the failures counter."""

    SYFT_NOT_FOUND = "syft_not_found"
    SYFT_TIMEOUT = "syft_timeout"
    SYFT_NONZERO_EXIT = "syft_nonzero_exit"
    SOURCE_NOT_FOUND = "source_not_found"
    AUTH_DENIED = "auth_denied"
    INTERNAL_ERROR = "internal_error"


# ---------------------------------------------------------------------------
# Component-count bucketing
# ---------------------------------------------------------------------------

_SIZE_BUCKET_BOUNDARIES: tuple[tuple[int, str], ...] = (
    (10, "xs"),
    (100, "small"),
    (1_000, "medium"),
    (5_000, "large"),
)


def sbom_size_bucket(component_count: int) -> str:
    """Map a component count to one of the five D7 LOCKED buckets.

    Bucket scheme (D7, round 6 closure 2026-06-12):

    >>> sbom_size_bucket(5)
    'xs'
    >>> sbom_size_bucket(10)
    'small'
    >>> sbom_size_bucket(100)
    'medium'
    >>> sbom_size_bucket(4_999)
    'large'
    >>> sbom_size_bucket(5_000)
    'xlarge'
    >>> sbom_size_bucket(50_000)
    'xlarge'
    """
    if component_count < 0:
        # Defensive — the analyzer never produces negative counts.
        return "xs"
    for ceiling, label in _SIZE_BUCKET_BOUNDARIES:
        if component_count < ceiling:
            return label
    return "xlarge"


# ---------------------------------------------------------------------------
# Ecosystem inference from a PURL prefix
# ---------------------------------------------------------------------------

_PURL_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "pkg:npm": Ecosystem.NPM,
    "pkg:pypi": Ecosystem.PYPI,
    "pkg:maven": Ecosystem.MAVEN,
    "pkg:nuget": Ecosystem.NUGET,
    "pkg:golang": Ecosystem.GO,
    "pkg:cargo": Ecosystem.CARGO,
    "pkg:gem": Ecosystem.RUBYGEMS,
    "pkg:composer": Ecosystem.COMPOSER,
    "pkg:conan": Ecosystem.CONAN,
    "pkg:apk": Ecosystem.APK,
    "pkg:deb": Ecosystem.DEB,
    "pkg:rpm": Ecosystem.RPM,
    "pkg:generic": Ecosystem.GENERIC,
    "pkg:oci": Ecosystem.GENERIC,
}


def ecosystem_from_purl(purl: Optional[str]) -> Ecosystem:
    """Translate a PURL prefix to a PlatformArchitect ecosystem enum value.

    Returns :attr:`Ecosystem.UNKNOWN` for ``None``, empty, or unknown
    PURLs. PURLs we recognise fall through to the matching enum.
    """
    if not purl:
        return Ecosystem.UNKNOWN
    head = purl.split("?", 1)[0]
    for prefix, eco in _PURL_TO_ECOSYSTEM.items():
        if head.startswith(prefix):
            return eco
    return Ecosystem.UNKNOWN


# ---------------------------------------------------------------------------
# Failure-reason inference
# ---------------------------------------------------------------------------


def failure_reason_from_exception(exc: BaseException) -> FailureReason:
    """Map a runtime exception to the bounded ``FailureReason`` enum.

    Anything we don't recognise falls through to
    :attr:`FailureReason.INTERNAL_ERROR` so the counter has a
    catch-all label without exploding cardinality.
    """
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "notfound" in name or "not found" in msg or "syft" in name.lower() and "not" in msg:
        return FailureReason.SYFT_NOT_FOUND
    if "timeout" in name or "timeout" in msg:
        return FailureReason.SYFT_TIMEOUT
    if "syft" in name.lower() and "exit" in msg:
        return FailureReason.SYFT_NONZERO_EXIT
    if "source" in name.lower() or "source" in msg:
        return FailureReason.SOURCE_NOT_FOUND
    if "auth" in name.lower() or "forbidden" in msg or "unauthor" in msg:
        return FailureReason.AUTH_DENIED
    return FailureReason.INTERNAL_ERROR
