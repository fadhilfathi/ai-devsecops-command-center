"""S2.8 hardening — per-feed audit log tests.

The audit log is a tamper-evident JSONL stream. Every feed run
produces a single event with: feed, fetched_at, record_count,
accepted_count, rejected_count, signature_valid, validator_version,
rejected_reasons, tenant_id, ingest_run_id. Events are append-only
and the file is rotated when it crosses ``max_bytes``.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vuln_intel.audit import FeedAuditEvent, FeedAuditLog, build_audit_event
from vuln_intel.validators import ValidationResult


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


# ---------------------------------------------------------------------------
# Append + read round-trip
# ---------------------------------------------------------------------------
def test_audit_log_append_and_read(audit_path: Path) -> None:
    log = FeedAuditLog(audit_path)
    ev = FeedAuditEvent(
        feed="nvd",
        fetched_at=datetime.now(UTC).isoformat(),
        record_count=10,
        accepted_count=9,
        rejected_count=1,
        signature_valid=False,
        validator_version="s2.8.0",
        tenant_id="default",
        ingest_run_id="run-1",
        rejected_reasons={"schema_violation": 1},
    )
    log.append(ev)
    events = log.read()
    assert len(events) == 1
    assert events[0].feed == "nvd"
    assert events[0].record_count == 10
    assert events[0].rejected_reasons == {"schema_violation": 1}


# ---------------------------------------------------------------------------
# Concurrent appends are byte-safe (no interleaved lines)
# ---------------------------------------------------------------------------
def test_audit_log_concurrent_appends(audit_path: Path) -> None:
    import threading

    log = FeedAuditLog(audit_path)

    def append(i: int) -> None:
        ev = FeedAuditEvent(
            feed="nvd",
            fetched_at=datetime.now(UTC).isoformat(),
            record_count=1,
            accepted_count=1,
            rejected_count=0,
            signature_valid=False,
            validator_version="s2.8.0",
            tenant_id="default",
            ingest_run_id=f"run-{i}",
        )
        log.append(ev)

    threads = [threading.Thread(target=append, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = log.read()
    assert len(events) == 20
    # Every line must be a valid JSON object
    for ev_file in audit_path.read_text().splitlines():
        json.loads(ev_file)  # raises on corruption


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------
def test_audit_log_rotation(audit_path: Path) -> None:
    # Tiny max_bytes forces rotation after the first event
    log = FeedAuditLog(audit_path, max_bytes=200)
    for i in range(5):
        ev = FeedAuditEvent(
            feed="nvd",
            fetched_at=datetime.now(UTC).isoformat(),
            record_count=1,
            accepted_count=1,
            rejected_count=0,
            signature_valid=False,
            validator_version="s2.8.0",
            tenant_id="default",
            ingest_run_id=f"run-{i}",
        )
        log.append(ev)
    # Either we wrote to a rotated file or the active one
    rotated = list(audit_path.parent.glob("audit.jsonl.*"))
    assert rotated, "expected a rotated audit file"
    assert audit_path.exists()  # active file is the post-rotation one


# ---------------------------------------------------------------------------
# build_audit_event counts accepted/rejected from ValidationResult objects
# ---------------------------------------------------------------------------
def test_build_audit_event_counts() -> None:
    results = [
        ValidationResult(valid=True, record_id="CVE-2024-0001"),
        ValidationResult(valid=True, record_id="CVE-2024-0002"),
        ValidationResult(
            valid=False,
            record_id="CVE-2024-0003",
            errors=("id: bad pattern",),
            rejected_reason="schema_violation",
        ),
        ValidationResult(
            valid=False,
            record_id="CVE-2024-0004",
            errors=("depth exceeded",),
            rejected_reason="depth_exceeded",
        ),
    ]
    ev = build_audit_event(
        feed="nvd",
        records=None,
        results=results,
        tenant_id="acme",
    )
    assert ev.feed == "nvd"
    assert ev.record_count == 4
    assert ev.accepted_count == 2
    assert ev.rejected_count == 2
    assert ev.rejected_reasons == {"schema_violation": 1, "depth_exceeded": 1}
    assert ev.tenant_id == "acme"
    assert ev.ingest_run_id  # auto-generated


# ---------------------------------------------------------------------------
# Event JSONL line is one line, no embedded newlines
# ---------------------------------------------------------------------------
def test_audit_event_is_single_line() -> None:
    ev = FeedAuditEvent(
        feed="ghsa",
        fetched_at="2024-06-01T00:00:00+00:00",
        record_count=1,
        accepted_count=0,
        rejected_count=1,
        signature_valid=False,
        validator_version="s2.8.0",
        tenant_id="default",
        ingest_run_id="run-x",
    )
    line = ev.to_jsonl()
    assert "\n" not in line
    json.loads(line)  # round-trip parse


# ---------------------------------------------------------------------------
# Read skips schema-drift rows gracefully
# ---------------------------------------------------------------------------
def test_audit_read_skips_invalid_rows(audit_path: Path) -> None:
    audit_path.write_text(
        '{"feed":"nvd","fetched_at":"2024-01-01","record_count":1,'
        '"accepted_count":1,"rejected_count":0,"signature_valid":false,'
        '"validator_version":"s2.8.0","tenant_id":"default","ingest_run_id":"r1"}\n'
        "this is not json\n"
        '{"feed":"ghsa","fetched_at":"2024-01-02","record_count":1,'
        '"accepted_count":1,"rejected_count":0,"signature_valid":false,'
        '"validator_version":"s2.8.0","tenant_id":"default","ingest_run_id":"r2"}\n'
    )
    log = FeedAuditLog(audit_path)
    events = log.read()
    # Invalid JSON row is skipped
    assert len(events) == 2
    feeds = {e.feed for e in events}
    assert feeds == {"nvd", "ghsa"}
