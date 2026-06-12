"""Live integration test — only runs if ``syft`` is on $PATH.

These tests verify the real end-to-end behavior of the wrapper against
the real Syft binary. They are skipped in CI by default and can be
enabled by setting ``SBOM_RUN_LIVE_TESTS=1`` in the environment.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from sbom_generator.config import Settings
from sbom_generator.models.request import GenerateRequest, SourceRef, SourceType
from sbom_generator.models.sbom import SBOMFormat
from sbom_generator.syft import SyftRunner, resolve_syft, get_syft_version

pytestmark = pytest.mark.skipif(
    shutil.which("syft") is None and not os.environ.get("SYFT_BINARY"),
    reason="syft binary not available",
)
pytestmark = pytest.mark.skipif(
    os.environ.get("SBOM_RUN_LIVE_TESTS") != "1",
    reason="set SBOM_RUN_LIVE_TESTS=1 to run live integration tests",
)


@pytest.fixture
async def runner():
    binary = resolve_syft(os.environ.get("SYFT_BINARY", "syft"))
    import asyncio

    sem = asyncio.Semaphore(1)
    r = SyftRunner(binary=binary, semaphore=sem)
    await r.warmup()
    return r


@pytest.mark.asyncio
async def test_syft_version_probe():
    version = await get_syft_version(resolve_syft())
    assert version is not None
    assert "." in version


@pytest.mark.asyncio
async def test_syft_scan_local_directory(runner, tmp_path: Path):
    # Drop a tiny package.json so Syft has something to find.
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "name": "live-test",
                "version": "0.0.1",
                "dependencies": {"lodash": "4.17.21"},
            }
        )
    )
    req = GenerateRequest(
        source=SourceRef(type=SourceType.DIRECTORY, value=str(tmp_path)),
    )
    result = await runner.run(req, fmt=SBOMFormat.SYFT_JSON, timeout=120)
    names = {c.name for c in result.sbom.components}
    assert "lodash" in names, f"expected lodash in {names}"
    assert result.sbom.format == SBOMFormat.SYFT_JSON
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_syft_scan_produces_cyclonedx(runner, tmp_path: Path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "x", "dependencies": {"lodash": "4.17.21"}}))
    req = GenerateRequest(
        source=SourceRef(type=SourceType.DIRECTORY, value=str(tmp_path)),
        formats=[SBOMFormat.CYCLONEDX_JSON],
    )
    result = await runner.run(req, fmt=SBOMFormat.CYCLONEDX_JSON, timeout=120)
    # In CycloneDX mode Syft writes a top-level "bomFormat" field.
    # That is the strongest signal that we requested the right format.
    assert result.raw.get("bomFormat") == "CycloneDX"
    assert result.raw.get("specVersion") == "1.5"
    assert result.sbom.format == SBOMFormat.CYCLONEDX_JSON
