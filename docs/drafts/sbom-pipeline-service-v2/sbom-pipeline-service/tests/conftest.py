"""Shared pytest fixtures for the SBOM pipeline service test suite."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_syft_payload() -> Dict[str, Any]:
    return json.loads((FIXTURES / "sample-syft.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def sample_cyclonedx() -> str:
    return (FIXTURES / "sample-cyclonedx.json").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def sample_spdx() -> str:
    return (FIXTURES / "sample-spdx.spdx").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


# ---------------------------------------------------------------------------
# In-memory test infrastructure
# ---------------------------------------------------------------------------


class _FakeSyft:
    """Fake SyftRunner — returns a canned SyftResult without spawning a process."""

    binary_path = "/fake/syft"

    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[Any] = []

    async def warmup(self) -> str:
        return "1.6.0-fake"

    async def scan(self, parsed, fmt=None, timeout=600, include_dev=False, exclude_paths=None):
        self.calls.append(parsed)
        from sbom_pipeline.syft_wrapper import SyftResult
        from sbom_pipeline.models import ecosystem_from_purl

        # Compute dominant ecosystem like the real runner does.
        counts: Dict[str, int] = {}
        for art in self._payload.get("artifacts") or []:
            eco = ecosystem_from_purl(art.get("purl")).value
            counts[eco] = counts.get(eco, 0) + 1
        dominant = max(counts.items(), key=lambda kv: kv[1])[0] if counts else "unknown"
        return SyftResult(
            raw=self._payload,
            raw_text=json.dumps(self._payload),
            elapsed_ms=42,
            command=["fake", "syft", parsed.value],
            warnings=[],
            exit_code=0,
            dominant_ecosystem=dominant,
        )


@pytest.fixture
def fake_syft(sample_syft_payload):
    return _FakeSyft(sample_syft_payload)


@pytest.fixture
def event_loop():
    """A fresh event loop per test for the async infra."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
