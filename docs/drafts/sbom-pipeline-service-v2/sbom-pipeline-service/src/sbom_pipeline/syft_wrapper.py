"""Async wrapper around the Anchore Syft CLI.

Syft is the de-facto SBOM generator for container images, filesystems,
git repos, and individual lockfiles. It exposes a stable JSON schema
(``syft-json``) and can transcode to CycloneDX / SPDX. We deliberately
do **not** import the Go library — that would couple our deployment
artifact to a Syft Go-build step. We spawn the ``syft`` CLI as a
subprocess so:

* the binary can be swapped (Syft, Trivy, cdxgen) without code changes
* the same image runs in CI, in the dev container, and in the cluster
* Syft's cataloger plugins are picked up automatically (new ecosystems
  appear in Syft releases, not in our service).

Public surface
==============

* :class:`SyftRunner`    — owns the subprocess, semaphore, and the
                           ``$PATH`` lookup.
* :class:`SyftResult`    — strongly-typed result wrapper.
* :func:`resolve_syft`   — finds the binary on ``$PATH`` or accepts
                           an explicit override.
* :func:`get_syft_version` — used by :func:`/healthz` and unit tests.
* :data:`SUPPORTED_LOCKFILES` — the lockfile filenames we recognize,
                                mapped to the cataloger hint we pass
                                to ``--catalogers package``.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sbom_pipeline.errors import (
    SyftExecutionError,
    SyftNotFoundError,
    SyftTimeoutError,
)
from sbom_pipeline.models import (
    ParsedSource,
    SBOMFormat,
    SourceKind,
    ecosystem_from_purl,
)

__all__ = [
    "SyftRunner",
    "SyftResult",
    "SUPPORTED_LOCKFILES",
    "get_syft_version",
    "resolve_syft",
]


# ---------------------------------------------------------------------------
# Lockfile catalogue
# ---------------------------------------------------------------------------

#: Mapping of well-known lockfile filenames → cataloger hint for Syft.
SUPPORTED_LOCKFILES: Dict[str, str] = {
    "package-lock.json": "package",
    "npm-shrinkwrap.json": "package",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lockb": "bun",
    "requirements.txt": "pip",
    "Pipfile.lock": "pipenv",
    "poetry.lock": "poetry",
    "pdm.lock": "pdm",
    "uv.lock": "uv",
    "setup.py": "python",
    "pyproject.toml": "python",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "gradle.lockfile": "gradle",
    "ivy.xml": "ivy",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "composer.lock": "php-composer",
    "Gemfile.lock": "ruby-gemfile",
    "packages.lock.json": "dotnet",
    "project.assets.json": "dotnet",
    "paket.lock": "paket",
    "mix.lock": "mix",
    "rebar.lock": "rebar",
    "pubspec.lock": "dart-pub",
    "Package.resolved": "swift",
    "cabal.project.freeze": "haskell",
    "stack.yaml.lock": "haskell",
    "conan.lock": "conan",
    "vcpkg.json": "vcpkg",
}


# ---------------------------------------------------------------------------
# Pure helpers (no I/O — fully unit-testable)
# ---------------------------------------------------------------------------


def _syft_target(parsed: ParsedSource) -> str:
    """Map a :class:`ParsedSource` to the target string Syft expects.

    * ``docker:nginx:1.25``           → ``nginx:1.25``
    * ``docker:nginx``                → ``registry:nginx:latest``
    * ``docker:nginx@sha256:abc``     → ``nginx@sha256:abc``
    * ``fs:/var/lib/myapp``           → ``dir:/var/lib/myapp``
    * ``lockfile:/tmp/pkg.json``      → ``file:/tmp/pkg.json``
    * ``git:https://…/r.git``         → ``https://…/r.git``
    * ``git:/local/repo``             → ``/local/repo``
    """
    if parsed.kind is SourceKind.DOCKER:
        value = parsed.value
        if "@sha256:" in value:
            return value
        if ":" in value:
            return value
        return f"registry:{value}:latest"

    if parsed.kind is SourceKind.FILESYSTEM:
        return f"dir:{parsed.value}"

    if parsed.kind is SourceKind.LOCKFILE:
        return f"file:{parsed.value}"

    if parsed.kind is SourceKind.GIT:
        return parsed.value

    return parsed.value


def _format_to_syft_flag(fmt: SBOMFormat) -> Tuple[str, str]:
    """Translate :class:`SBOMFormat` to Syft's ``-o`` flag value."""
    if fmt is SBOMFormat.CYCLONEDX_JSON:
        return "cyclonedx-json", "application/vnd.cyclonedx+json"
    if fmt is SBOMFormat.CYCLONEDX_XML:
        return "cyclonedx-xml", "application/vnd.cyclonedx+xml"
    if fmt is SBOMFormat.SPDX_JSON:
        return "spdx-json", "application/spdx+json"
    if fmt is SBOMFormat.SPDX_TAG_VALUE:
        return "spdx-tag-value", "text/spdx"
    if fmt is SBOMFormat.SYFT_JSON:
        return "syft-json", "application/json"
    return "syft-json", "application/json"


def _build_command(
    binary: str,
    target: str,
    fmt: SBOMFormat,
    parsed: ParsedSource,
    *,
    exclude_paths: Optional[Sequence[str]] = None,
    include_dev: bool = False,
) -> List[str]:
    """Assemble the argv list that we will hand to ``exec``."""
    output_flag, _ = _format_to_syft_flag(fmt)
    cmd: List[str] = [binary, "scan", target, "-o", output_flag]

    if parsed.kind is SourceKind.DOCKER:
        cmd.extend(["--source", "docker"])

    if parsed.kind is SourceKind.GIT:
        cmd.extend(["--git-commit", "HEAD"])

    if parsed.kind is SourceKind.LOCKFILE:
        lockfile_name = Path(parsed.value).name
        cataloger = SUPPORTED_LOCKFILES.get(lockfile_name)
        if cataloger:
            cmd.extend(["--catalogers", cataloger])

    for path in exclude_paths or ():
        cmd.extend(["-x", path])

    if not include_dev:
        cmd.extend(["--select-catalogers", "+dev"])

    return cmd


def _dominant_ecosystem(raw: Dict[str, Any]) -> str:
    """Pick the most-common purl type from a Syft raw payload."""
    counts: Dict[str, int] = {}
    for artifact in raw.get("artifacts") or ():
        purl = artifact.get("purl") if isinstance(artifact, dict) else None
        eco = ecosystem_from_purl(purl).value
        counts[eco] = counts.get(eco, 0) + 1
    if not counts:
        return "unknown"
    return max(counts.items(), key=lambda kv: kv[1])[0]


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SyftResult:
    """Strongly-typed result of a single Syft invocation."""

    raw: Optional[Dict[str, Any]] = None
    raw_text: str = ""
    elapsed_ms: int = 0
    command: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    exit_code: int = 0
    dominant_ecosystem: str = "unknown"


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------


def resolve_syft(override: Optional[str] = None) -> str:
    """Locate the ``syft`` binary.

    Resolution order:

    1. ``override`` argument (typically ``settings.syft_binary``).
    2. ``$SYFT_BINARY`` environment variable.
    3. ``$PATH`` lookup via :func:`shutil.which`.

    Raises:
        SyftNotFoundError: if no binary can be located.
    """
    if override:
        path = Path(override)
        if not path.is_file():
            raise SyftNotFoundError(
                f"syft binary not found at {override!r}",
                details={"path": override},
            )
        return str(path)

    env = os.environ.get("SYFT_BINARY")
    if env:
        path = Path(env)
        if not path.is_file():
            raise SyftNotFoundError(
                f"syft binary not found at $SYFT_BINARY={env!r}",
                details={"path": env},
            )
        return str(path)

    found = shutil.which("syft")
    if not found:
        raise SyftNotFoundError(
            "syft binary not found on $PATH and no $SYFT_BINARY set",
            details={"path": "syft"},
        )
    return found


async def get_syft_version(binary: str) -> str:
    """Run ``<binary> version`` and return the version string."""
    proc = await asyncio.create_subprocess_exec(
        binary,
        "version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    text = stdout.decode("utf-8", errors="replace").strip()
    parts = text.split()
    return parts[1] if len(parts) >= 2 else text


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


class SyftRunner:
    """Async wrapper around the Syft CLI.

    Construction is cheap; the runner does **not** probe the binary
    until :meth:`warmup` is called. This keeps ``app.state`` setup
    synchronous and lets us defer ``$PATH`` lookups until the lifespan
    context manager is up.

    Args:
        binary:    absolute path to the Syft binary, or ``"syft"`` to
                   defer to :func:`resolve_syft`.
        semaphore: bounded-concurrency semaphore. Pass one from the
                   application state so we don't fork-bomb the host
                   when 50 concurrent ``/sbom/generate`` requests
                   come in. ``None`` disables the limit.
    """

    def __init__(
        self,
        *,
        binary: str = "syft",
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> None:
        self._explicit_binary = binary
        self._semaphore = semaphore
        self._resolved: Optional[str] = None
        self._version: Optional[str] = None

    @property
    def binary_path(self) -> str:
        """Absolute path to the Syft binary.

        Resolution is lazy — we only touch ``$PATH`` in
        :meth:`warmup` and the property returns the configured value
        (which may be ``"syft"``) when not yet resolved.
        """
        return self._resolved or self._explicit_binary

    @property
    def version(self) -> Optional[str]:
        return self._version

    async def warmup(self) -> str:
        """Resolve the binary and cache its version.

        Idempotent. Returns the version string (e.g. ``"1.6.0"``).
        """
        self._resolved = resolve_syft(self._explicit_binary)
        self._version = await get_syft_version(self._resolved)
        return self._version

    async def scan(
        self,
        parsed: ParsedSource,
        fmt: Optional[SBOMFormat] = None,
        *,
        timeout: float = 600.0,
        include_dev: bool = False,
        exclude_paths: Optional[Sequence[str]] = None,
    ) -> SyftResult:
        """Run Syft against ``parsed`` and return a :class:`SyftResult`."""
        if self._resolved is None:
            self._resolved = resolve_syft(self._explicit_binary)

        output_format = fmt or SBOMFormat.CYCLONEDX_JSON
        target = _syft_target(parsed)
        cmd = _build_command(
            self._resolved,
            target,
            output_format,
            parsed,
            exclude_paths=exclude_paths,
            include_dev=include_dev,
        )

        async def _run() -> SyftResult:
            t0 = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise SyftTimeoutError(
                    f"syft scan timed out after {timeout:.0f}s",
                    details={"command": cmd, "timeout_s": timeout},
                ) from exc
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            raw_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            warnings = [
                line.strip()
                for line in stderr_text.splitlines()
                if line.strip()
            ]

            if proc.returncode != 0:
                raise SyftExecutionError(
                    f"syft exited {proc.returncode}: {stderr_text[:200]!r}",
                    details={
                        "command": cmd,
                        "exit_code": proc.returncode,
                        "stderr_tail": warnings[-5:],
                    },
                )

            raw: Optional[Dict[str, Any]] = None
            if output_format in (
                SBOMFormat.CYCLONEDX_JSON,
                SBOMFormat.SPDX_JSON,
                SBOMFormat.SYFT_JSON,
            ):
                try:
                    raw = json.loads(raw_text)
                except json.JSONDecodeError as exc:
                    raise SyftExecutionError(
                        "syft emitted invalid JSON",
                        details={"error": str(exc), "head": raw_text[:200]},
                    ) from exc

            return SyftResult(
                raw=raw,
                raw_text=raw_text,
                elapsed_ms=elapsed_ms,
                command=cmd,
                warnings=warnings,
                exit_code=proc.returncode or 0,
                dominant_ecosystem=_dominant_ecosystem(raw or {}),
            )

        if self._semaphore is None:
            return await _run()
        async with self._semaphore:
            return await _run()
