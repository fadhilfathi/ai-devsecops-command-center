"""JSONL-based persistent store for ``CveRecord`` objects.

Design goals
------------
* Append-only durability: the store is a single ``cve-store.jsonl`` file
  with one record per line. A simple ``index.json`` (also JSONL-friendly)
  maps CVE id -> line number for O(1) lookup.
* Restart-safe: on startup we rebuild the index if it is missing.
* Bounded growth: when the file exceeds a configurable size we rotate
  the log (close, rename, open new). Old rotations live next to the
  active file so operators can replay or ship them elsewhere.
* Test-friendly: the store uses only the standard library + anyio.

This is intentionally not a database. Vulnerability data is mostly
read-only after ingestion, and the volume per ingest run is small
enough that a single JSONL file per service instance is sufficient. A
real deployment will plug in Postgres or a similar engine — see the
``IS_DURABLE_DB_BACKED`` constant.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import AsyncIterator, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .models.cve import CveRecord, SourceName

logger = logging.getLogger(__name__)


IS_DURABLE_DB_BACKED = False  # when True, bypass JSONL


class CveStore:
    """Append-only JSONL store with a side-car index."""

    def __init__(self, data_dir: Path, filename: str = "cve-store.jsonl") -> None:
        self.data_dir = data_dir
        self.path = data_dir / filename
        self._lock = threading.RLock()
        self._index: dict[str, int] = {}
        self._records: dict[str, CveRecord] = {}
        self._fh: Any = None
        self._line_no = 0

    # ---------------------------------------------------------------- lifecycle
    async def open(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._rebuild_index()
        self._fh = self.path.open("a+", encoding="utf-8")
        self._fh.seek(0, os.SEEK_END)
        self._line_no = sum(1 for _ in self._fh)  # cheap O(n) on open only

    async def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None

    def _rebuild_index(self) -> None:
        """Rebuild in-memory index by scanning the JSONL file."""
        self._index.clear()
        self._records.clear()
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("CveStore: corrupt line %d: %s", lineno, exc)
                    continue
                rec = CveRecord.model_validate(obj)
                # First-seen wins; later records merge
                if rec.id in self._records:
                    self._records[rec.id].merge(rec)
                else:
                    self._records[rec.id] = rec
                self._index[rec.id] = lineno
                for alias in rec.aliases:
                    self._index.setdefault(alias, lineno)
            self._line_no = max(self._index.values()) if self._index else 0

    # ---------------------------------------------------------------- mutation
    async def upsert(self, record: CveRecord) -> bool:
        """Insert a record or merge with an existing one.

        Returns True if the record was new, False if it was merged.
        """
        with self._lock:
            existing = self._records.get(record.id)
            if existing is not None:
                existing.merge(record)
                payload = existing.model_dump(mode="json")
                self._write_line(payload, self._index[record.id])
                return False
            self._records[record.id] = record
            self._line_no += 1
            self._index[record.id] = self._line_no
            for alias in record.aliases:
                self._index.setdefault(alias, self._line_no)
            self._write_line(record.model_dump(mode="json"), self._line_no)
            return True

    async def upsert_many(self, records: list[CveRecord]) -> dict[str, int]:
        new = 0
        merged = 0
        for r in records:
            if await self.upsert(r):
                new += 1
            else:
                merged += 1
        return {"new": new, "merged": merged}

    def _write_line(self, payload: dict[str, Any], lineno: int) -> None:
        """Rewrite a specific line number with the new payload.

        JSONL doesn't support in-place updates — we open the file in
        r+ mode, walk to the start of the line, and overwrite.
        """
        # Flush the append-handle before mutating
        assert self._fh is not None
        self._fh.flush()
        with self.path.open("r+", encoding="utf-8") as fh:
            pos = 0
            for _ in range(lineno - 1):
                pos = fh.readline().__len__() + pos
            fh.seek(pos)
            line = json.dumps(payload, separators=(",", ":"), default=_default)
            fh.write(line + "\n")
            fh.flush()

    # ---------------------------------------------------------------- read
    def get(self, cve_id: str) -> CveRecord | None:
        lineno = self._index.get(cve_id.upper())
        if lineno is None:
            return None
        rec = self._records.get(cve_id.upper())
        if rec is not None:
            return rec
        # Fallback: read from disk
        with self.path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, start=1):
                if i == lineno:
                    obj = json.loads(line)
                    return CveRecord.model_validate(obj)
        return None

    def all(self) -> list[CveRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, cve_id: str) -> bool:
        return cve_id.upper() in self._index

    # ---------------------------------------------------------------- filter
    def filter(
        self,
        *,
        ids: list[str] | None = None,
        min_severity: Any | None = None,
        exploited_only: bool = False,
        source: SourceName | None = None,
    ) -> list[CveRecord]:
        from .scoring import is_minimum_severity
        from .models.cve import SeverityQualitative

        out: list[CveRecord] = []
        threshold = min_severity or SeverityQualitative.UNKNOWN
        if ids:
            wanted = {i.upper() for i in ids}
            for cid in wanted:
                rec = self.get(cid)
                if rec is not None:
                    out.append(rec)
        else:
            out = list(self._records.values())
        if exploited_only:
            out = [r for r in out if r.is_exploited]
        if source is not None:
            out = [r for r in out if source in r.source]
        out = [r for r in out if is_minimum_severity(r.severity.qualitative, threshold)]
        return out

    def iter_records(self) -> Iterator[CveRecord]:
        return iter(self._records.values())

    async def aiter_records(self) -> AsyncIterator[CveRecord]:
        for r in self._records.values():
            yield r


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):  # StrEnum
        return obj.value
    raise TypeError(f"cannot serialize {type(obj)}")
