"""In-process TTL cache used to avoid hammering upstream sources."""
from __future__ import annotations

import time
from collections import OrderedDict
from threading import RLock
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class TtlCache(Generic[K, V]):
    """Thread-safe LRU cache with per-entry TTL.

    Used for both the EPSS response cache and the source metadata
    cache. We intentionally keep this in-process for now — when
    horizontally scaled we'll switch to a Redis-backed implementation
    via the same interface.
    """

    def __init__(self, max_size: int = 4096) -> None:
        self._max_size = max_size
        self._store: OrderedDict[K, tuple[float, V]] = OrderedDict()
        self._lock = RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: K, default: V | None = None) -> V | None:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return default
            expires_at, value = entry
            if expires_at < now:
                self._store.pop(key, None)
                self.misses += 1
                return default
            self._store.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: K, value: V, ttl_s: int) -> None:
        if ttl_s <= 0:
            return
        expires_at = time.monotonic() + ttl_s
        with self._lock:
            self._store[key] = (expires_at, value)
            self._store.move_to_end(key)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self.hits = 0
            self.misses = 0

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def __len__(self) -> int:
        return len(self._store)
