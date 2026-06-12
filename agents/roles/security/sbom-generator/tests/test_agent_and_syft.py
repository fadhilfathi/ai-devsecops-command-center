"""Tests for the in-memory bus and the Syft CLI argument builder."""

from __future__ import annotations

import asyncio
import json

import pytest

from sbom_generator.agent import InMemoryBus
from sbom_generator.models.request import GenerateRequest, SourceRef, SourceType
from sbom_generator.syft import _build_command, _syft_target, SUPPORTED_LOCKFILES


def test_in_memory_bus_publish_subscribe():
    bus = InMemoryBus()
    received = []

    async def handler(payload):
        received.append(payload)

    async def run():
        await bus.connect()
        await bus.subscribe("test.subject", handler)
        msg_id = await bus.publish("test.subject", {"hello": "world"})
        await asyncio.sleep(0.05)  # let handler run
        return msg_id

    msg_id = asyncio.run(run())
    assert msg_id
    assert received and received[0]["hello"] == "world"


def test_in_memory_bus_healthy_reflects_state():
    bus = InMemoryBus()
    assert asyncio.run(bus.healthy()) is False
    asyncio.run(bus.connect())
    assert asyncio.run(bus.healthy()) is True
    asyncio.run(bus.close())
    assert asyncio.run(bus.healthy()) is False


def test_syft_target_directory():
    assert _syft_target(SourceRef(type=SourceType.DIRECTORY, value="/x")) == "dir:/x"


def test_syft_target_file():
    assert _syft_target(SourceRef(type=SourceType.FILE, value="/x/y")) == "file:/x/y"


def test_syft_target_archive():
    assert _syft_target(SourceRef(type=SourceType.ARCHIVE, value="/x.tgz")) == "archive:/x.tgz"


def test_syft_target_registry():
    assert _syft_target(SourceRef(type=SourceType.REGISTRY, value="r.example.com")) == "registry:r.example.com"


def test_syft_target_docker_appends_latest():
    assert _syft_target(SourceRef(type=SourceType.DOCKER_IMAGE, value="nginx")) == "nginx:latest"


def test_syft_target_docker_preserves_tag():
    assert _syft_target(SourceRef(type=SourceType.DOCKER_IMAGE, value="nginx:1.25")) == "nginx:1.25"


def test_syft_target_git_passthrough():
    assert _syft_target(SourceRef(type=SourceType.GIT_REPOSITORY, value="https://x/y.git")) == "https://x/y.git"


def test_build_command_default_format():
    req = GenerateRequest(source=SourceRef(type=SourceType.DIRECTORY, value="/x"))
    cmd = _build_command("syft", req, "dir:/x", req.formats[0])
    assert cmd[0] == "syft"
    assert "scan" in cmd
    assert "dir:/x" in cmd
    assert "-o" in cmd and "cyclonedx-json" in cmd


def test_build_command_excludes_dev_dependencies_by_default():
    req = GenerateRequest(source=SourceRef(type=SourceType.DIRECTORY, value="/x"))
    cmd = _build_command("syft", req, "dir:/x", req.formats[0])
    # Syft 1.x does not have a ``--select-catalogers`` flag; we
    # narrow the cataloger set with ``-c package`` to drop dev
    # catalogers. The test asserts that some cataloger-narrowing
    # knob is on the command line.
    assert ("-c", "package") in [tuple(cmd[i:i+2]) for i in range(len(cmd)-1)]


def test_build_command_includes_excludes():
    req = GenerateRequest(
        source=SourceRef(type=SourceType.DIRECTORY, value="/x"),
        exclude_paths=["node_modules", ".git"],
    )
    cmd = _build_command("syft", req, "dir:/x", req.formats[0])
    assert cmd.count("-x") == 2


def test_build_command_picks_catalogers():
    req = GenerateRequest(
        source=SourceRef(type=SourceType.DIRECTORY, value="/x"),
        catalogs=["package", "file"],
    )
    cmd = _build_command("syft", req, "dir:/x", req.formats[0])
    assert "--catalogers" in cmd


def test_build_command_git_uses_head():
    req = GenerateRequest(
        source=SourceRef(type=SourceType.GIT_REPOSITORY, value="https://x/y.git")
    )
    cmd = _build_command("syft", req, "https://x/y.git", req.formats[0])
    assert "--git-commit" in cmd
    assert "HEAD" in cmd


def test_supported_lockfiles_is_a_realistic_set():
    expected = {
        "package-lock.json",
        "yarn.lock",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "pom.xml",
        "Cargo.lock",
        "go.sum",
    }
    assert expected.issubset(SUPPORTED_LOCKFILES.keys())
