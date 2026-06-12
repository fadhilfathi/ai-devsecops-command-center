"""Cross-source consensus for CVE severity scoring.

The SecurityArchitect's S2.8 threat model (``docs/threat-models/
s2-security-mitigations.md`` § 3.5 + § 3.6) requires that a CVE only
be eligible for HIGH or CRITICAL severity when **at least two** of
the upstream sources {NVD, GHSA, OSV} corroborate it. Single-source
HIGH/CRITICAL classifications are tagged ``unofficial`` so that the
Security UI can flag them for human review and the risk engine can
down-weight them in cluster scoring.

**Threat-model references (S2.8):**
* **§ 3.5** — per-feed JSON-Schema validation: T-02 (CVE feed
  poisoning) is mitigated by ``validators.py``; the consensus rule
  is a *secondary* defence against an attacker who manages to push
  a single poisoned feed past the validator.
* **§ 3.6** — "flag, don't downgrade" policy. The ``unofficial``
  tag is added to the record but the stored ``severity`` field is
  never silently downgraded. The 4-condition ``auto_actionable``
  gate at the security-service :4003 projection is what gates
  auto-remediation; the wire ``auto_actionable`` field is the
  security-service's responsibility (see GitOpsManager sign-off
  2026-06-12).

The module is intentionally framework-free (no FastAPI, no Pydantic)
so it can be unit-tested in isolation and reused from the CLI.

Examples
--------
>>> from vuln_intel.consensus import CrossSourceConsensus
>>> cs = CrossSourceConsensus()
>>> decision = cs.evaluate({"nvd", "ghsa"}, severity="CRITICAL")
>>> decision.is_high_or_critical, decision.is_unofficial
(True, False)

>>> decision = cs.evaluate({"osv"}, severity="CRITICAL")
>>> decision.is_high_or_critical, decision.is_unofficial
(True, True)
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Sources that count toward the consensus tally. EPSS / KEV are
# enrichment signals, not severity sources, so they are not included.
CONSENSUS_SOURCES: frozenset[str] = frozenset({"nvd", "ghsa", "osv"})

# Severity bands that require cross-source consensus.
_HIGH_OR_CRITICAL: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Minimum number of distinct sources required to corroborate a
# HIGH/CRITICAL classification. This is a security control, not a
# tuning knob — it is intentionally hard-coded.
MIN_SOURCES_FOR_HIGH_CRITICAL: int = 2


@dataclass(slots=True, frozen=True)
class ConsensusDecision:
    """Outcome of evaluating a CVE's cross-source consensus."""

    cve_id: str
    severity: str
    sources: tuple[str, ...]
    source_count: int
    is_high_or_critical: bool
    is_unofficial: bool
    # ``reason`` is a short label for metrics/audit purposes:
    # "consensus_ok" | "single_source_high_critical" | "below_high".
    reason: str


class CrossSourceConsensus:
    """Apply the cross-source consensus rule.

    Stateless and thread-safe. Construction is cheap; reuse one
    instance across the process.
    """

    __slots__ = ()

    def evaluate(
        self,
        sources: Iterable[str],
        severity: str,
        cve_id: str = "",
    ) -> ConsensusDecision:
        """Return a :class:`ConsensusDecision` for the given inputs.

        Parameters
        ----------
        sources:
            Iterable of source names that have corroborated this CVE.
            Unknown names are ignored; only entries in
            :data:`CONSENSUS_SOURCES` are counted.
        severity:
            The aggregated severity label (``"NONE"``..``"CRITICAL"``).
        cve_id:
            Optional CVE id — included in the returned decision for
            logging and audit purposes.
        """
        normalised = tuple(
            sorted(
                s.lower()
                for s in sources
                if isinstance(s, str) and s.lower() in CONSENSUS_SOURCES
            )
        )
        source_count = len(normalised)
        is_high_crit = severity.upper() in _HIGH_OR_CRITICAL

        if not is_high_crit:
            reason = "below_high"
            is_unofficial = False
        elif source_count >= MIN_SOURCES_FOR_HIGH_CRITICAL:
            reason = "consensus_ok"
            is_unofficial = False
        else:
            reason = "single_source_high_critical"
            is_unofficial = True

        return ConsensusDecision(
            cve_id=cve_id,
            severity=severity.upper(),
            sources=normalised,
            source_count=source_count,
            is_high_or_critical=is_high_crit,
            is_unofficial=is_unofficial,
            reason=reason,
        )

    def is_unofficial(self, sources: Iterable[str], severity: str) -> bool:
        """Convenience predicate — True when HIGH/CRITICAL lacks consensus."""
        return self.evaluate(sources, severity).is_unofficial


# ---------------------------------------------------------------------------
# Tagging helper
# ---------------------------------------------------------------------------
def consensus_tag(record_tags: Iterable[str] | None, decision: ConsensusDecision) -> list[str]:
    """Append the consensus tag to a record's tag list (idempotent)."""
    tags = list(record_tags or [])
    if decision.is_unofficial and "unofficial" not in tags:
        tags.append("unofficial")
    elif not decision.is_unofficial and "unofficial" in tags:
        tags.remove("unofficial")
    if decision.is_high_or_critical and decision.source_count >= MIN_SOURCES_FOR_HIGH_CRITICAL:
        if "corroborated" not in tags:
            tags.append("corroborated")
    return tags
