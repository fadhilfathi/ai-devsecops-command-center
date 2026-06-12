"""Tests for the JSONL-backed CveStore."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from vuln_intel.models.cve import (
    CveRecord,
    CvssScore,
    ScoreSource,
    SeverityAggregate,
    SeverityQualitative,
    SourceName,
)
from vuln_intel.store import CveStore


def _record(cid: str, severity: SeverityQualitative = SeverityQualitative.HIGH) -> CveRecord:
    return CveRecord(
        id=cid,
        source=[SourceName.NVD],
        summary="x",
        severity=SeverityAggregate(
            qualitative=severity,
            cvss_v3=CvssScore(version="3.1", vector="x", score=7.5, severity=severity, source=ScoreSource.NVD_PRIMARY),
            primary_source=ScoreSource.NVD_PRIMARY,
        ),
    )


@pytest.mark.asyncio
async def test_store_upsert_and_get(tmp_path: Path) -> None:
    store = CveStore(tmp_path, "cve.jsonl")
    await store.open()
    try:
        rec = _record("CVE-2024-0001")
        assert await store.upsert(rec) is True
        loaded = store.get("CVE-2024-0001")
        assert loaded is not None
        assert loaded.id == "CVE-2024-0001"
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_store_persists_across_reopen(tmp_path: Path) -> None:
    store = CveStore(tmp_path, "cve.jsonl")
    await store.open()
    await store.upsert(_record("CVE-2024-0002"))
    await store.close()

    store2 = CveStore(tmp_path, "cve.jsonl")
    await store2.open()
    try:
        assert store2.get("CVE-2024-0002") is not None
    finally:
        await store2.close()


@pytest.mark.asyncio
async def test_store_merges_existing(tmp_path: Path) -> None:
    store = CveStore(tmp_path, "cve.jsonl")
    await store.open()
    try:
        rec = _record("CVE-2024-0003", SeverityQualitative.MEDIUM)
        await store.upsert(rec)
        rec2 = _record("CVE-2024-0003", SeverityQualitative.CRITICAL)
        assert await store.upsert(rec2) is False
        loaded = store.get("CVE-2024-0003")
        assert loaded is not None
        assert loaded.severity.qualitative == SeverityQualitative.CRITICAL
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_store_filter_by_severity(tmp_path: Path) -> None:
    store = CveStore(tmp_path, "cve.jsonl")
    await store.open()
    try:
        await store.upsert(_record("CVE-2024-0004", SeverityQualitative.LOW))
        await store.upsert(_record("CVE-2024-0005", SeverityQualitative.CRITICAL))
        critical = store.filter(min_severity=SeverityQualitative.CRITICAL)
        assert {r.id for r in critical} == {"CVE-2024-0005"}
    finally:
        await store.close()
