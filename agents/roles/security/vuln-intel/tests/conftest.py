"""Shared pytest fixtures."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure no auth is required by default in tests
os.environ.setdefault("VULN_INTEL_AUTH_REQUIRED", "false")
os.environ.setdefault("VULN_INTEL_DATA_DIR", str(Path("/tmp/vuln-intel-tests")))
os.environ.setdefault("VULN_INTEL_STORE_FILENAME", "cve-store.jsonl")

from vuln_intel.api.app import create_app  # noqa: E402
from vuln_intel.config import Settings, reset_settings_cache  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    reset_settings_cache()
    return Settings(data_dir=tmp_path, store_filename="cve-store.jsonl", auth_required=False)


@pytest_asyncio.fixture
async def app_client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield client
