"""Shared pytest fixtures for dependency-intel."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("DEP_INTEL_AUTH_REQUIRED", "false")
os.environ.setdefault("DEP_INTEL_DATA_DIR", str(Path("/tmp/dep-intel-tests")))
os.environ.setdefault("DEP_INTEL_GRAPH_FILENAME", "graphs.jsonl")

from dependency_intel.api.app import create_app  # noqa: E402
from dependency_intel.config import Settings, reset_settings_cache  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    reset_settings_cache()
    return Settings(
        data_dir=tmp_path,
        graph_filename="graphs.jsonl",
        auth_required=False,
        vuln_intel_url="http://localhost:9999",  # not used in unit tests
    )


@pytest_asyncio.fixture
async def app_client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield client
