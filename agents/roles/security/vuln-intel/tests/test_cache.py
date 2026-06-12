"""Tests for the in-process TTL cache."""
from __future__ import annotations

import time

import pytest

from vuln_intel.cache import TtlCache


def test_set_and_get() -> None:
    c: TtlCache[str, int] = TtlCache()
    c.set("k", 42, ttl_s=60)
    assert c.get("k") == 42


def test_ttl_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    c: TtlCache[str, int] = TtlCache()
    c.set("k", 42, ttl_s=1)
    # Simulate the passage of time by tampering with the internal clock
    real_monotonic = time.monotonic
    t = {"now": real_monotonic()}
    monkeypatch.setattr("time.monotonic", lambda: t["now"])
    c.set("k", 42, ttl_s=10)
    t["now"] += 11
    assert c.get("k") is None


def test_lru_eviction() -> None:
    c: TtlCache[int, int] = TtlCache(max_size=3)
    c.set(1, 1, ttl_s=60)
    c.set(2, 2, ttl_s=60)
    c.set(3, 3, ttl_s=60)
    c.get(1)
    c.get(2)
    c.set(4, 4, ttl_s=60)  # should evict 3 (oldest unused)
    assert c.get(3) is None
    assert c.get(1) == 1
    assert c.get(2) == 2
    assert c.get(4) == 4


def test_hit_ratio() -> None:
    c: TtlCache[str, int] = TtlCache()
    c.set("a", 1, ttl_s=60)
    c.get("a")
    c.get("missing")
    assert 0 <= c.hit_ratio <= 1
    assert c.hits == 1
    assert c.misses == 1
