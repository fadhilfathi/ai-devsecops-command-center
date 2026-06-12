"""Graph storage — JSONL-backed with an in-memory index.

Same design as vuln-intel's :class:`CveStore` but storing :class:`DependencyGraph`
objects instead.
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

from .models.graph import DependencyGraph, GraphEdge, GraphNode

logger = logging.getLogger(__name__)


class GraphStore:
    def __init__(self, data_dir: Path, filename: str = "graphs.jsonl") -> None:
        self.data_dir = data_dir
        self.path = data_dir / filename
        self._lock = threading.RLock()
        self._graphs: dict[str, DependencyGraph] = {}
        self._index: dict[str, int] = {}
        self._line_no = 0
        self._fh: Any = None

    async def open(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._rebuild_index()
        self._fh = self.path.open("a+", encoding="utf-8")
        self._fh.seek(0, os.SEEK_END)

    async def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None

    def _rebuild_index(self) -> None:
        self._graphs.clear()
        self._index.clear()
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
                    logger.warning("GraphStore: corrupt line %d: %s", lineno, exc)
                    continue
                graph = DependencyGraph.model_validate(obj)
                self._graphs[graph.id] = graph
                self._index[graph.id] = lineno
                for sbom in graph.sbom_ids:
                    self._index.setdefault(f"sbom:{sbom}", lineno)
            self._line_no = max(self._index.values()) if self._index else 0

    def get(self, graph_id: str) -> DependencyGraph | None:
        return self._graphs.get(graph_id)

    def get_by_sbom(self, sbom_id: str) -> DependencyGraph | None:
        lineno = self._index.get(f"sbom:{sbom_id}")
        if lineno is None:
            return None
        # Re-derive which graph carries the SBOM
        for g in self._graphs.values():
            if sbom_id in g.sbom_ids:
                return g
        return None

    def all(self) -> list[DependencyGraph]:
        return list(self._graphs.values())

    def __len__(self) -> int:
        return len(self._graphs)

    async def save(self, graph: DependencyGraph) -> None:
        with self._lock:
            existing = self._graphs.get(graph.id)
            graph.updated_at = datetime.utcnow()
            payload = graph.model_dump(mode="json", by_alias=True)
            if existing is not None:
                lineno = self._index[graph.id]
                self._rewrite_line(lineno, payload)
            else:
                self._line_no += 1
                self._index[graph.id] = self._line_no
                for sbom in graph.sbom_ids:
                    self._index.setdefault(f"sbom:{sbom}", self._line_no)
                assert self._fh is not None
                self._fh.write(json.dumps(payload, default=_default) + "\n")
                self._fh.flush()
            self._graphs[graph.id] = graph

    def _rewrite_line(self, lineno: int, payload: dict[str, Any]) -> None:
        assert self._fh is not None
        self._fh.flush()
        with self.path.open("r+", encoding="utf-8") as fh:
            pos = 0
            for _ in range(lineno - 1):
                pos += len(fh.readline())
            fh.seek(pos)
            fh.write(json.dumps(payload, default=_default) + "\n")
            fh.flush()

    def iter_graphs(self) -> Iterator[DependencyGraph]:
        return iter(self._graphs.values())

    async def aiter_graphs(self) -> AsyncIterator[DependencyGraph]:
        for g in self._graphs.values():
            yield g


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):  # StrEnum
        return obj.value
    raise TypeError(f"cannot serialize {type(obj)}")
