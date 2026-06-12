"""Per-feed audit log (append-only JSONL).

S2.8 requires a tamper-evident audit trail of every feed run:

* ``feed``              — the source name (nvd, ghsa, osv, epss, kev)
* ``fetched_at``        — ISO-8601 UTC timestamp of the upstream fetch
* ``record_count``      — number of records processed
* ``accepted_count``    — number of records that passed validation
* ``rejected_count``    — number of records rejected, broken down by reason
* ``signature_valid``   — True if the upstream signature was verified
* ``validator_version`` — version stamp from :mod:`validators`
* ``tenant_id``         — the tenant context for this run
* ``ingest_run_id``     — unique per-run id (UUID4) for correlation

The log is written to a JSONL file (one event per line) with an
in-process lock so concurrent workers can't interleave bytes inside a
single event. The file is rotated by size by the caller — the audit
log is **not** a structured stream; it's a stack of events.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .telemetry import get_logger

logger = get_logger(__name__)

# Default audit-log file name. Overridable via env var.
DEFAULT_AUDIT_FILENAME: Final[str] = "vuln-intel-audit.jsonl"


@dataclass(slots=True)
class FeedAuditEvent:
    """A single per-feed audit record (one line of JSONL)."""

    feed: str
    fetched_at: str
    record_count: int
    accepted_count: int
    rejected_count: int
    signature_valid: bool
    validator_version: str
    tenant_id: str
    ingest_run_id: str
    rejected_reasons: dict[str, int] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> str:
        """Render the event as a single-line JSON string."""
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    def to_dict(self) -> dict[str, Any]:
        """Render the event as a plain dict (e.g. for the audit endpoint)."""
        return asdict(self)


class FeedAuditLog:
    """Append-only JSONL audit log with per-process locking.

    Parameters
    ----------
    path:
        File to write to. Parent directories are created on first write.
    max_bytes:
        Soft size limit — when the file would exceed this, the existing
        file is rotated to ``<path>.<timestamp>`` and a fresh one is
        started. ``0`` disables rotation.
    """

    def __init__(self, path: Path | str, max_bytes: int = 64 * 1024 * 1024) -> None:
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def _rotate_if_needed(self) -> None:
        if self._max_bytes <= 0:
            return
        try:
            size = self._path.stat().st_size
        except FileNotFoundError:
            return
        if size >= self._max_bytes:
            ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            rotated = self._path.with_name(f"{self._path.name}.{ts}")
            try:
                os.replace(self._path, rotated)
                logger.info("audit_rotated rotated=%s prior_bytes=%s", str(rotated), size)
            except OSError as exc:  # pragma: no cover — disk failure
                logger.warning("audit_rotate_failed error=%s", str(exc))

    def append(self, event: FeedAuditEvent) -> None:
        """Write a single event to the log (atomic per-line via the lock)."""
        line = event.to_jsonl() + "\n"
        with self._lock:
            self._rotate_if_needed()
            # Open in append-binary mode so we never partially overwrite.
            with self._path.open("ab") as fh:
                fh.write(line.encode("utf-8"))
        logger.debug(
            "audit_written feed=%s accepted=%s rejected=%s run_id=%s",
            event.feed,
            event.accepted_count,
            event.rejected_count,
            event.ingest_run_id,
        )

    def read(self) -> list[FeedAuditEvent]:
        """Read all events (used by tests and by the audit endpoint)."""
        if not self._path.exists():
            return []
        events: list[FeedAuditEvent] = []
        with self._path.open("rb") as fh:
            for raw in fh:
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                try:
                    events.append(FeedAuditEvent(**payload))
                except TypeError:
                    # Schema drift between versions — skip the row.
                    continue
        return events


# ---------------------------------------------------------------------------
# Helper for the ingest pipeline
# ---------------------------------------------------------------------------
def build_audit_event(
    feed: str,
    records: Iterable[Any],
    results: Iterable[Any],
    *,
    tenant_id: str,
    signature_valid: bool = False,
    validator_version: str = "s2.8.0",
    fetched_at: datetime | None = None,
    extra: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> FeedAuditEvent:
    """Build a :class:`FeedAuditEvent` from a list of validation results.

    ``results`` is an iterable of objects exposing ``.valid`` and
    ``.rejected_reason`` (e.g. :class:`validators.ValidationResult`).
    """
    results_list = list(results)
    reasons: Counter[str] = Counter()
    accepted = 0
    for r in results_list:
        if getattr(r, "valid", False):
            accepted += 1
        else:
            reason = getattr(r, "rejected_reason", None) or "unknown"
            reasons[reason] += 1
    return FeedAuditEvent(
        feed=feed,
        fetched_at=(fetched_at or datetime.now(UTC)).isoformat(),
        record_count=len(results_list),
        accepted_count=accepted,
        rejected_count=len(results_list) - accepted,
        signature_valid=signature_valid,
        validator_version=validator_version,
        tenant_id=tenant_id,
        ingest_run_id=run_id or str(uuid.uuid4()),
        rejected_reasons=dict(reasons),
        extra=extra or {},
    )
