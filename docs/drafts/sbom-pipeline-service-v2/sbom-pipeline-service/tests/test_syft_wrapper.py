"""Tests for the Syft CLI wrapper.

The wrapper has two distinct surfaces:

* Pure helpers (``_syft_target``, ``_build_command``, ``_dominant_ecosystem``)
  — fully unit-testable without a real Syft binary.
* The :class:`SyftRunner` async surface — tested here with a fake
  ``syft`` binary on ``$PATH`` only when the integration test env
  is enabled.

The :class:`resolve_syft` and :func:`get_syft_version` are tested by
the integration suite, not here, to keep the unit tests hermetic.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sbom_pipeline.models import (
    ParsedSource,
    SBOMFormat,
    SourceKind,
    parse_source,
    ecosystem_from_purl,
)
from sbom_pipeline.syft_wrapper import (
    SUPPORTED_LOCKFILES,
    SyftRunner,
    _build_command,
    _dominant_ecosystem,
    _syft_target,
)


# ---------------------------------------------------------------------------
# Source-prefix parsing (delegated to models.parse_source, but we verify
# that the Syft wrapper consumes ParsedSource objects correctly).
# ---------------------------------------------------------------------------


def test_syft_target_docker_preserves_tag():
    p = parse_source("docker:nginx:1.25")
    assert _syft_target(p) == "nginx:1.25"


def test_syft_target_docker_appends_latest_when_no_tag():
    p = parse_source("docker:nginx")
    # We coerce ``docker:nginx`` to ``registry:nginx:latest`` so Syft
    # goes through the registry look-up path.
    assert _syft_target(p) == "registry:nginx:latest"


def test_syft_target_docker_preserves_digest():
    p = parse_source("docker:nginx@sha256:abc")
    assert _syft_target(p) == "nginx@sha256:abc"


def test_syft_target_filesystem_uses_dir_prefix():
    p = parse_source("fs:/var/lib/myapp")
    assert _syft_target(p) == "dir:/var/lib/myapp"


def test_syft_target_lockfile_uses_file_prefix():
    p = parse_source("lockfile:/tmp/package-lock.json")
    assert _syft_target(p) == "file:/tmp/package-lock.json"


def test_syft_target_git_passthrough():
    p = parse_source("git:https://github.com/aionrs/aionrs.git")
    assert _syft_target(p) == "https://github.com/aionrs/aionrs.git"


def test_syft_target_git_local_path():
    p = parse_source("git:/local/repo")
    assert _syft_target(p) == "/local/repo"


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------


def test_build_command_default_uses_cyclonedx_json():
    p = parse_source("docker:nginx:1.25")
    cmd = _build_command("syft", _syft_target(p), SBOMFormat.CYCLONEDX_JSON, p)
    assert "scan" in cmd
    assert "nginx:1.25" in cmd
    assert "-o" in cmd and "cyclonedx-json" in cmd


def test_build_command_docker_sets_source_flag():
    p = parse_source("docker:nginx")
    cmd = _build_command("syft", _syft_target(p), SBOMFormat.SYFT_JSON, p)
    assert "--source" in cmd
    assert "docker" in cmd


def test_build_command_git_uses_head_commit():
    p = parse_source("git:https://github.com/a/b.git")
    cmd = _build_command("syft", _syft_target(p), SBOMFormat.SPDX_JSON, p)
    assert "--git-commit" in cmd
    assert "HEAD" in cmd


def test_build_command_lockfile_uses_package_catalogers():
    p = parse_source("lockfile:/tmp/package-lock.json")
    cmd = _build_command("syft", _syft_target(p), SBOMFormat.CYCLONEDX_JSON, p)
    assert "--catalogers" in cmd
    assert "package" in cmd[cmd.index("--catalogers") + 1]


def test_build_command_includes_exclude_paths():
    p = parse_source("fs:/var/lib/myapp")
    cmd = _build_command(
        "syft", _syft_target(p), SBOMFormat.SYFT_JSON, p,
        exclude_paths=("node_modules", ".git"),
    )
    assert cmd.count("-x") == 2


def test_build_command_skips_dev_dependencies_by_default():
    p = parse_source("fs:/var/lib/myapp")
    cmd = _build_command("syft", _syft_target(p), SBOMFormat.SYFT_JSON, p)
    assert "--select-catalogers" in cmd


# ---------------------------------------------------------------------------
# Ecosystem extraction
# ---------------------------------------------------------------------------


def test_dominant_ecosystem_uses_most_common_purl():
    raw = {
        "artifacts": [
            {"purl": "pkg:npm/lodash@4.17.21"},
            {"purl": "pkg:npm/express@4"},
            {"purl": "pkg:pypi/requests@2.31.0"},
        ]
    }
    assert _dominant_ecosystem(raw) == "npm"


def test_dominant_ecosystem_handles_no_purl():
    raw = {"artifacts": [{"name": "x"}]}
    assert _dominant_ecosystem(raw) == "unknown"


def test_dominant_ecosystem_handles_empty():
    assert _dominant_ecosystem({}) == "unknown"
    assert _dominant_ecosystem({"artifacts": []}) == "unknown"


def test_ecosystem_from_purl_table():
    assert ecosystem_from_purl("pkg:npm/lodash@4").value == "npm"
    assert ecosystem_from_purl("pkg:pypi/requests@2.31.0").value == "pypi"
    assert ecosystem_from_purl("pkg:maven/com.foo/bar@1").value == "maven"
    assert ecosystem_from_purl("pkg:cargo/serde@1.0").value == "cargo"
    assert ecosystem_from_purl("pkg:golang/github.com/x/y@1.0").value == "go"
    assert ecosystem_from_purl(None).value == "unknown"
    assert ecosystem_from_purl("not-a-purl").value == "unknown"


# ---------------------------------------------------------------------------
# Supported lockfiles
# ---------------------------------------------------------------------------


def test_supported_lockfiles_includes_common_kinds():
    expected = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "pom.xml",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
    }
    assert expected.issubset(SUPPORTED_LOCKFILES.keys())


# ---------------------------------------------------------------------------
# Runner wiring (no live binary)
# ---------------------------------------------------------------------------


def test_syft_runner_resolves_binary_path(monkeypatch, tmp_path):
    fake = tmp_path / "syft"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    import asyncio

    runner = SyftRunner(binary=str(fake), semaphore=asyncio.Semaphore(1))
    assert runner.binary_path == str(fake)
