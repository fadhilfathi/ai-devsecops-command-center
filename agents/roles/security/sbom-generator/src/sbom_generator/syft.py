"""Asynchronous wrapper around the Anchore Syft CLI.

Syft exposes its full functionality as a single binary with a JSON
output mode. We invoke it via ``asyncio.create_subprocess_exec`` so that
the FastAPI service stays non-blocking. The wrapper:

* Locates the binary at boot and reports the resolved path/version.
* Streams stdout into a memory buffer (Syft JSON is small relative to
  the artifacts it scans, but we cap it to avoid memory pressure on
  huge images).
* Returns the parsed JSON, the elapsed time, and a list of warnings
  extracted from stderr.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sbom_generator.errors import (
    SyftExecutionError,
    SyftNotFoundError,
    SyftTimeoutError,
    ValidationError,
)
from sbom_generator.models.request import GenerateRequest, SourceRef, SourceType
from sbom_generator.models.sbom import SBOM, SBOMFormat, normalize_syft_output

logger = logging.getLogger("sbom_generator.syft")


# Cap stdout to avoid pathological allocations. 256 MiB is generous for
# any real-world SBOM we have observed to date.
_MAX_STDOUT_BYTES = 256 * 1024 * 1024


@dataclass
class SyftResult:
    """The outcome of a single Syft invocation."""

    sbom: SBOM
    raw: Dict[str, Any]
    elapsed_ms: int
    command: List[str]
    warnings: List[str] = field(default_factory=list)
    exit_code: int = 0


def resolve_syft(binary: str = "syft") -> str:
    """Return the absolute path to the Syft binary, raising if missing."""
    found = shutil.which(binary) or (
        binary if os.path.isabs(binary) and os.access(binary, os.X_OK) else None
    )
    if not found:
        raise SyftNotFoundError(
            f"syft binary not found on PATH and SYFT_BINARY is not set",
            details={"looked_up": binary},
        )
    return found


async def get_syft_version(binary: str) -> Optional[str]:
    """Return the Syft version string, or ``None`` if it can't be parsed."""
    proc = await asyncio.create_subprocess_exec(
        binary, "version", "-o", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return data.get("version") or data.get("syft_version") or None


# ---------------------------------------------------------------------------
# Source kind → Syft CLI argument mapping
# ---------------------------------------------------------------------------


def _syft_target(source: SourceRef) -> str:
    """Convert a :class:`SourceRef` into the positional argument Syft wants."""
    kind = source.type
    value = source.value
    if kind == SourceType.DOCKER_IMAGE:
        # Syft accepts ``registry/repo:tag`` directly.
        if ":" not in value and "@" not in value:
            return f"{value}:latest"
        return value
    if kind == SourceType.OCI_IMAGE:
        # Same as docker but with explicit ``--source oci`` flag.
        return value
    if kind == SourceType.GIT_REPOSITORY:
        return value
    if kind == SourceType.DIRECTORY:
        return f"dir:{value}"
    if kind == SourceType.FILE:
        return f"file:{value}"
    if kind == SourceType.ARCHIVE:
        return f"archive:{value}"
    if kind == SourceType.REGISTRY:
        # ``registry:hostname`` causes Syft to enumerate the catalog.
        return f"registry:{value}"
    raise ValidationError(
        f"unsupported source.type={kind!r}",
        details={"valid": [
            SourceType.DIRECTORY,
            SourceType.FILE,
            SourceType.DOCKER_IMAGE,
            SourceType.OCI_IMAGE,
            SourceType.GIT_REPOSITORY,
            SourceType.ARCHIVE,
            SourceType.REGISTRY,
        ]},
    )


def _build_command(
    binary: str,
    request: GenerateRequest,
    target: str,
    fmt: SBOMFormat,
) -> List[str]:
    """Compose the Syft CLI command line for the given request."""
    cmd: List[str] = [binary, "scan", target, "--quiet"]

    if request.source.type == SourceType.OCI_IMAGE:
        cmd.extend(["--source", "oci"])
    elif request.source.type == SourceType.DOCKER_IMAGE:
        cmd.extend(["--source", "docker"])

    if request.source.type == SourceType.REGISTRY:
        # Registry scans need to be in a non-default "registry" mode.
        cmd.extend(["--source", "registry"])

    # Output format selection. Syft supports the standard SPDX / CycloneDX
    # enum values plus its own JSON.
    fmt_map = {
        SBOMFormat.CYCLONEDX_JSON: "cyclonedx-json",
        SBOMFormat.CYCLONEDX_XML: "cyclonedx-xml",
        SBOMFormat.SPDX_JSON: "spdx-json",
        SBOMFormat.SPDX_TAG_VALUE: "spdx-tag-value",
        SBOMFormat.SYFT_JSON: "json",
    }
    cmd.extend(["-o", fmt_map[fmt]])

    if request.catalogs:
        cmd.extend(["--catalogers", ",".join(request.catalogs)])

    if request.exclude_paths:
        for path in request.exclude_paths:
            cmd.extend(["-x", path])

    if request.scan_root:
        # The platform sends the workspace path as a scope hint.
        cmd.extend(["--scope", "squashed"])

    if not request.include_dev_dependencies:
        # Skip dev dependencies by default for prod scans.
        cmd.extend(["-c", "package"])

    # Always use HEAD git commits for reproducibility.
    if request.source.type == SourceType.GIT_REPOSITORY:
        cmd.extend(["--git-commit", "HEAD"])

    return cmd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SyftRunner:
    """Stateful runner that owns the binary path and concurrency limits."""

    def __init__(self, binary: str, semaphore: asyncio.Semaphore) -> None:
        # Resolve lazily — this lets the agent class instantiate
        # cleanly in unit tests, CI smoke, and dev environments
        # where Syft may not be on $PATH yet. The binary is
        # actually looked up the first time :meth:`run` is called.
        self._explicit_binary = binary
        self._binary: Optional[str] = None
        self._semaphore = semaphore
        self._version: Optional[str] = None

    def _ensure_resolved(self) -> str:
        if self._binary is None:
            self._binary = resolve_syft(self._explicit_binary)
        return self._binary

    @property
    def binary_path(self) -> str:
        # Prefer the resolved path; fall back to whatever was passed
        # in (so :class:`SBOMGeneratorAgent` can be constructed for
        # inspection without a live Syft binary).
        return self._binary or self._explicit_binary

    @binary_path.setter
    def binary_path(self, value: str) -> None:
        # Test hook — lets unit tests override the resolved binary
        # path without going through the full ``resolve_syft`` lookup.
        # Production code should never use this.
        self._binary = value
        self._version = None  # force re-warmup if a test needs it

    async def warmup(self) -> Optional[str]:
        """Cache the version string so /healthz can report it cheaply.

        Returns ``None`` (and leaves ``binary_path`` as the configured
        value) if the binary cannot be exec'd — typical for unit
        tests and dev environments where Syft is not yet on $PATH.
        The /healthz endpoint treats ``version == None`` as a soft
        "binary not yet located" signal and reports the path
        anyway, so the rest of the service stays useful.
        """
        if self._version is not None:
            return self._version
        try:
            self._binary = self._ensure_resolved()
            self._version = await get_syft_version(self._binary)
        except (FileNotFoundError, OSError) as exc:
            logger.warning("syft warmup failed: %s", exc)
            self._version = None
        return self._version

    async def run(
        self,
        request: GenerateRequest,
        fmt: SBOMFormat = SBOMFormat.SYFT_JSON,
        timeout: int = 600,
        env: Optional[Dict[str, str]] = None,
    ) -> SyftResult:
        request.validate_source()
        target = _syft_target(request.source)
        binary = self._ensure_resolved()
        cmd = _build_command(binary, request, target, fmt)

        logger.info("invoking syft: %s", " ".join(cmd))
        start = time.monotonic()
        async with self._semaphore:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, **(env or {})},
                )
            except FileNotFoundError as exc:
                raise SyftNotFoundError(str(exc), details={"binary": binary})

            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise SyftTimeoutError(
                    f"syft scan exceeded {timeout}s timeout",
                    details={"command": cmd, "timeout": timeout},
                ) from exc

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if len(stdout_b) > _MAX_STDOUT_BYTES:
            raise SyftExecutionError(
                "syft output exceeded internal size cap",
                details={"cap_bytes": _MAX_STDOUT_BYTES},
            )

        try:
            raw = json.loads(stdout_b) if stdout_b else {}
        except json.JSONDecodeError as exc:
            raise SyftExecutionError(
                "syft produced non-JSON output",
                details={"stderr": stderr_b.decode("utf-8", errors="replace")[:2000]},
            ) from exc

        if proc.returncode != 0 and not raw:
            raise SyftExecutionError(
                f"syft exited with code {proc.returncode}",
                details={
                    "stderr": stderr_b.decode("utf-8", errors="replace")[:2000],
                    "command": cmd,
                },
            )

        warnings = _extract_warnings(stderr_b.decode("utf-8", errors="replace"))
        sbom = normalize_syft_output(raw)
        sbom.format = fmt
        if request.tenant_id:
            sbom.metadata.tenant_id = request.tenant_id
        if request.metadata:
            sbom.metadata.properties = dict(request.metadata)  # type: ignore[attr-defined]

        return SyftResult(
            sbom=sbom,
            raw=raw,
            elapsed_ms=elapsed_ms,
            command=cmd,
            warnings=warnings,
            exit_code=proc.returncode or 0,
        )


def _extract_warnings(stderr_text: str) -> List[str]:
    """Pull human-readable warnings from Syft's stderr."""
    if not stderr_text:
        return []
    warnings: List[str] = []
    for line in stderr_text.splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if any(token in low for token in ("warn", "deprecat", "skip")):
            warnings.append(line)
    return warnings


# ---------------------------------------------------------------------------
# Inline scanner — used for source kinds that don't need the Syft binary
# ---------------------------------------------------------------------------


@dataclass
class InlinePackage:
    """A tiny package record used by the inline scanners."""

    name: str
    version: str
    purl: Optional[str] = None
    licenses: Sequence[str] = field(default_factory=list)


SUPPORTED_LOCKFILES = {
    ".npm/package-lock.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip",
    "requirements-test.txt": "pip",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Cargo.lock": "cargo",
    "go.sum": "gomod",
    "composer.lock": "composer",
    "Gemfile.lock": "bundler",
    "packages.lock.json": "nuget",
    "paket.lock": "paket",
    "mix.lock": "hex",
    "conan.lock": "conan",
    "renv.lock": "renv",
    "Pipfile": "pipfile",
}
