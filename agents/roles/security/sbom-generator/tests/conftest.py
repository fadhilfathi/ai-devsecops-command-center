"""Shared pytest fixtures for the SBOM generator test suite."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sample_syft_payload() -> dict:
    return json.loads((FIXTURES / "sample-syft.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def sample_cyclonedx() -> str:
    return (FIXTURES / "sample-cyclonedx.json").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES
