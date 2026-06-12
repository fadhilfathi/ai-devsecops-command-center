"""Event-bus aware agent for the SBOM generator.

The agent class wraps the :class:`SyftRunner` and is responsible for:

* Subscribing to ``sbom.generate`` requests on the event bus (NATS /
  Redis Streams) and producing ``sbom.generated`` events.
* Publishing lifecycle events (``agent.ready``, ``agent.unhealthy``).
* Honoring per-tenant rate limits and concurrency caps.

A best-effort in-process bus implementation is provided so the service
runs out-of-the-box without any external broker. Real deployments
should pass a :class:`BusClient` to :func:`create_app`.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional

from sbom_generator.metrics import (
    Ecosystem,
    FailureReason,
    Result,
    TargetType,
    failure_reason_from_exception,
    sbom_size_bucket,
)
from sbom_generator.metrics import SourceType as MetricsSourceType

from sbom_generator.config import Settings
from sbom_generator.models.request import GenerateRequest, SourceType
from sbom_generator.models.response import GenerateResponse
from sbom_generator.security.ssrf import assert_safe_target
from sbom_generator.syft import SyftRunner, SyftResult

logger = logging.getLogger("sbom_generator.agent")


# ---------------------------------------------------------------------------
# Bus abstraction
# ---------------------------------------------------------------------------


class BusClient:
    """Minimal interface every bus implementation must satisfy."""

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def publish(self, subject: str, payload: Dict[str, Any]) -> str: ...
    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None: ...
    async def healthy(self) -> bool: ...


class InMemoryBus(BusClient):
    """In-process bus for development and tests.

    Uses ``asyncio.Queue`` to deliver messages between local coroutines.
    Honors queue groups by broadcasting to all subscribers; in real
    deployments the broker would deliver each message to a single
    member of the group.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[[Dict[str, Any]], Awaitable[None]]]] = {}
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def close(self) -> None:
        self._connected = False
        self._subscribers.clear()

    async def publish(self, subject: str, payload: Dict[str, Any]) -> str:
        if not self._connected:
            raise RuntimeError("bus not connected")
        import uuid

        message_id = str(uuid.uuid4())
        await asyncio.sleep(0)  # yield control
        for handler in list(self._subscribers.get(subject, [])):
            asyncio.create_task(handler({**payload, "_id": message_id, "_subject": subject}))
        return message_id

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None:
        self._subscribers.setdefault(subject, []).append(handler)

    async def healthy(self) -> bool:
        return self._connected


class NATSClient(BusClient):
    """Thin NATS client wrapper.

    The real implementation lives in :mod:`aionrs.bus`. This class is
    the *contract* — if a real bus URL is configured, the service
    factory will dynamically import the production implementation.
    """

    def __init__(self, url: str) -> None:
        self._url = url
        self._nc: Any = None
        self._js: Any = None

    async def connect(self) -> None:
        try:
            import nats  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "nats-py is not installed; install with `pip install nats-py`"
            ) from exc
        self._nc = await nats.connect(self._url)
        self._js = self._nc.jetstream()

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.close()
            self._nc = None
            self._js = None

    async def publish(self, subject: str, payload: Dict[str, Any]) -> str:
        import json
        import uuid

        if self._js is not None:
            ack = await self._js.publish(subject, json.dumps(payload).encode("utf-8"))
            return ack.seq
        if self._nc is not None:
            await self._nc.publish(subject, json.dumps(payload).encode("utf-8"))
            return str(uuid.uuid4())
        raise RuntimeError("bus not connected")

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
        queue: Optional[str] = None,
    ) -> None:
        import json

        async def _wrapped(msg: Any) -> None:
            try:
                payload = json.loads(msg.data.decode("utf-8"))
            except Exception:  # noqa: BLE001
                payload = {"_raw": msg.data.decode("utf-8", errors="replace")}
            await handler(payload)

        if self._js is not None:
            await self._js.subscribe(subject, cb=_wrapped, queue=queue)
        elif self._nc is not None:
            await self._nc.subscribe(subject, cb=_wrapped, queue=queue)
        else:
            raise RuntimeError("bus not connected")

    async def healthy(self) -> bool:
        return self._nc is not None and not self._nc.is_closed


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


@dataclass
class JobRecord:
    request_id: str
    started_at: float
    finished_at: Optional[float] = None
    success: bool = False
    format: str = "cyclonedx-json"


class SBOMGeneratorAgent:
    """High-level façade combining the Syft runner and the bus."""

    def __init__(
        self,
        settings: Settings,
        runner: SyftRunner,
        bus: BusClient,
        telemetry: Any,
    ) -> None:
        self._settings = settings
        self._runner = runner
        self._bus = bus
        self._telemetry = telemetry
        self._active_jobs: List[JobRecord] = []

    # ---- Properties ----------------------------------------------------

    @property
    def active_job_count(self) -> int:
        return sum(1 for j in self._active_jobs if j.finished_at is None)

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def runner(self) -> SyftRunner:
        return self._runner

    @runner.setter
    def runner(self, value: SyftRunner) -> None:
        self._runner = value

    @property
    def bus(self) -> BusClient:
        return self._bus

    @bus.setter
    def bus(self, value: BusClient) -> None:
        self._bus = value

    @property
    def telemetry(self) -> Any:
        return self._telemetry

    @telemetry.setter
    def telemetry(self, value: Any) -> None:
        self._telemetry = value

    # ---- Lifecycle -----------------------------------------------------

    async def start(self) -> None:
        await self._bus.connect()
        await self._runner.warmup()
        await self._bus.subscribe(
            f"{self._settings.bus_subject_prefix}.requests",
            self._on_bus_request,
            queue="sbom-generators",
        )
        await self._bus.publish(
            f"{self._settings.bus_subject_prefix}.events",
            {
                "kind": "agent.ready",
                "service": self._settings.service_name,
                "version": "1.0.0",
                "syft_path": self._runner.binary_path,
            },
        )
        self._telemetry.event("agent.start", service=self._settings.service_name)

    async def stop(self) -> None:
        await self._bus.publish(
            f"{self._settings.bus_subject_prefix}.events",
            {
                "kind": "agent.stopping",
                "service": self._settings.service_name,
            },
        )
        await self._bus.close()
        self._telemetry.event("agent.stop", service=self._settings.service_name)

    # ---- Public methods ------------------------------------------------

    async def generate(self, request: GenerateRequest) -> GenerateResponse:
        """Run a single SBOM scan and serialize the results."""
        request.validate_source()

        # T-07 (S2.8): async SSRF defense.
        # The Pydantic validator at the model layer already rejected IP
        # literals and banned hostnames. Here we additionally resolve
        # hostnames and check that *no* returned A/AAAA record is in a
        # private/reserved range — this catches DNS rebinding attacks
        # where a hostname resolves to a private IP at request time.
        await self._ssrf_check(request)

        record = JobRecord(
            request_id="-",  # filled in by caller
            started_at=0.0,
        )
        self._active_jobs.append(record)

        # ---- S2.7-locked metric labels (build once, reuse) -------------
        # ``ecosystem`` is inferred from the dominant PURL of the
        # request's source kind (best-effort), or from the Syft
        # ``dominant_ecosystem`` once the scan finishes. ``format`` is
        # DEFERRED to Sprint 3 per the S2.7 D3 verdict.
        s2_7_source_type = _s2_7_source_type_for(request.source.type)
        s2_7_target_type = _s2_7_target_type_for(request.source.type)
        s2_7_repo_shape = (
            _s2_7_repo_shape_for(request.source.value)
            if s2_7_target_type is TargetType.GIT
            else "_unspecified"
        )
        s2_7_active_scans = self._telemetry.inc(
            "devsecops_sbom_active_scans",
            scanner_type=MetricsSourceType.SYFT.value,
        )
        self._telemetry.gauge(
            "devsecops_sbom_active_scans",
            value=1.0,
            scanner_type=MetricsSourceType.SYFT.value,
        )

        try:
            self._telemetry.inc("sbom_jobs_total", format=request.formats[0].value)
            with self._telemetry.span(
                "sbom.generate",
                source_type=request.source.type,
                source_value=request.source.value,
            ):
                async with _s2_7_active_scan(self._telemetry):
                    syft_result = await self._runner.run(
                        request=request,
                        fmt=request.formats[0],
                        timeout=self._settings.request_timeout_seconds,
                    )

            # S2.7: histogrammed in **seconds** (we observe ms and
            # divide; or the Telemetry wrapper exposes a
            # ``observe_seconds`` helper).
            self._telemetry.observe(
                "devsecops_sbom_generation_duration_seconds",
                value=syft_result.elapsed_ms / 1000.0,
                source_type=s2_7_source_type,
                result=Result.SUCCESS.value,
                ecosystem=syft_result.dominant_ecosystem,
                target_type=s2_7_target_type.value,
                repo_shape=s2_7_repo_shape,
            )
            # S2.7: components counter, bucket from the S2.7 5-bucket
            # scheme. ``unknown`` is what the analyzer falls back to
            # when there are no purls.
            self._telemetry.inc(
                "devsecops_sbom_components_total",
                sbom_size_bucket=sbom_size_bucket(len(syft_result.sbom.components)),
            )
            # Legacy v1 metrics — kept for the in-cluster
            # ``/metrics`` endpoint so existing dashboards don't
            # break during the cutover. Will be removed in Sprint 3
            # once the S2.7 dashboards are validated.
            self._telemetry.observe("syft_duration_ms", syft_result.elapsed_ms)
            self._telemetry.observe(
                "components_per_scan", len(syft_result.sbom.components)
            )
            record.success = True
            return await _build_response(request, syft_result, self._bus, self._settings)
        except Exception as exc:  # noqa: BLE001
            # S2.7: failure counter with bounded reasons.
            reason = failure_reason_from_exception(exc)
            self._telemetry.inc(
                "devsecops_sbom_scan_failures_total",
                reason=reason.value,
            )
            self._telemetry.observe(
                "devsecops_sbom_generation_duration_seconds",
                value=0.0,  # placeholder; the real elapsed_ms is hard to read
                source_type=s2_7_source_type,
                result=Result.FAILURE.value,
                ecosystem=Ecosystem.UNKNOWN.value,
                target_type=s2_7_target_type.value,
                repo_shape=s2_7_repo_shape,
            )
            self._telemetry.event(
                "sbom.generate.error",
                error_type=type(exc).__name__,
                error=str(exc),
                reason=reason.value,
            )
            raise
        finally:
            record.finished_at = 0.0  # timestamp set in response builder
            self._telemetry.gauge(
                "devsecops_sbom_active_scans",
                value=0.0,
                scanner_type=MetricsSourceType.SYFT.value,
            )

    # ---- T-07 SSRF defense (S2.8 hotfix) ---------------------------------

    _REMOTE_SOURCE_KINDS = frozenset(
        {
            SourceType.GIT_REPOSITORY,
            SourceType.DOCKER_IMAGE,
            SourceType.OCI_IMAGE,
            SourceType.REGISTRY,
        }
    )

    async def _ssrf_check(self, request: GenerateRequest) -> None:
        """Run the async SSRF defense for remote sources.

        For local-path sources (directory/file/archive), the SSRF check
        is unnecessary — Syft only reads from the local filesystem and
        no network egress occurs.

        For remote sources, ``assert_safe_target`` resolves the hostname
        and rejects any result whose IP falls in a private/reserved
        range. A timeout or resolution failure fails closed.
        """
        kind = request.source.type
        if kind not in self._REMOTE_SOURCE_KINDS:
            return

        ssrf = self._settings.ssrf
        target = request.source.value
        try:
            result = await assert_safe_target(
                target,
                allowlist=ssrf.git_host_allowlist,
                default_deny=ssrf.default_deny,
                dns_timeout_seconds=ssrf.dns_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            # Fail closed: any unexpected error in the SSRF check is
            # treated as a block. This is the safer default for a
            # defense-in-depth layer.
            logger.warning("SSRF check raised: %s", exc)
            self._telemetry.event(
                "sbom.ssrf.error",
                error_type=type(exc).__name__,
                error=str(exc),
                source_type=kind.value,
            )
            from sbom_generator.errors import SsrfBlockedError

            raise SsrfBlockedError(
                f"SSRF defense: unexpected error during target validation",
                details={"value": target, "error": str(exc)},
            ) from exc

        if not result.allowed:
            logger.warning(
                "SSRF block: source_type=%s target=%s reason=%s",
                kind.value,
                target,
                result.reason,
            )
            self._telemetry.event(
                "sbom.ssrf.blocked",
                source_type=kind.value,
                target=target,
                reason=result.reason,
            )
            from sbom_generator.errors import SsrfBlockedError

            raise SsrfBlockedError(
                f"SSRF defense: target rejected ({result.reason})",
                details={
                    "value": target,
                    "source_type": kind.value,
                    "reason": result.reason,
                    "resolved_addresses": list(result.resolved_addresses),
                },
            )
        # Allowed — log resolved addresses for forensics.
        if result.resolved_addresses:
            logger.info(
                "SSRF allowed: target=%s resolved=%s",
                target,
                result.resolved_addresses,
            )

    # ---- Bus handler ---------------------------------------------------

    async def _on_bus_request(self, payload: Dict[str, Any]) -> None:
        try:
            request = GenerateRequest.model_validate(payload)
            response = await self.generate(request)
            await self._bus.publish(
                f"{self._settings.bus_subject_prefix}.results",
                {
                    "request_id": response.request_id,
                    "job_id": response.job_id,
                    "status": "ok",
                    "components_count": response.components_count,
                    "format": response.format.value,
                },
            )
        except Exception as exc:  # noqa: BLE001
            self._telemetry.event("bus_request.error", error=str(exc))
            await self._bus.publish(
                f"{self._settings.bus_subject_prefix}.results",
                {
                    "status": "error",
                    "error": str(exc),
                    "request_id": payload.get("request_id"),
                },
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _build_response(
    request: GenerateRequest,
    syft_result: SyftResult,
    bus: BusClient,
    settings: Settings,
) -> GenerateResponse:
    """Construct the public response and publish the lifecycle event."""
    from sbom_generator.models.response import FormattedSBOM, GenerateResponse
    from sbom_generator import output as output_module
    from sbom_generator.models.sbom import SBOMFormat

    formats_out: List[FormattedSBOM] = []
    for fmt in request.formats:
        body, media = output_module.serialize(syft_result.sbom, fmt)
        formats_out.append(
            FormattedSBOM(
                format=fmt,
                media_type=media,
                body=body,
                byte_size=len(body.encode("utf-8")),
            )
        )

    distinct_licenses = {
        lic.id or lic.name or lic.expression
        for c in syft_result.sbom.components
        for lic in c.licenses
        if lic.id or lic.name or lic.expression
    }

    response = GenerateResponse(
        source_type=request.source.type,
        source_value=request.source.value,
        format=request.formats[0],
        components_count=len(syft_result.sbom.components),
        distinct_licenses=len(distinct_licenses),
        formats=formats_out,
        sbom=syft_result.sbom,
        warnings=syft_result.warnings,
    )

    try:
        # Build the **canonical** CycloneDX JSON body for fingerprinting
        # — the same byte sequence every consumer of the event will
        # see. RFC 8785 / JCS canonicalisation:
        # ``json.dumps(obj, sort_keys=True, separators=(",", ":"))``.
        # The GitOps auto-committer validates this fingerprint against
        # the on-disk SBOM file at ``security/sboms/<sbom_id>/``.
        from sbom_generator.formats.cyclonedx import to_cyclonedx_json
        import hashlib

        cyclonedx_body = next(
            (f.body for f in formats_out if f.format == SBOMFormat.CYCLONEDX_JSON),
            formats_out[0].body,
        )
        try:
            cyclonedx_dict = json.loads(cyclonedx_body)
        except (json.JSONDecodeError, ValueError):
            cyclonedx_dict = {"raw": cyclonedx_body}
        canonical = json.dumps(
            cyclonedx_dict, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        sbom_fingerprint = "sha256:" + hashlib.sha256(canonical).hexdigest()

        # sbom_id: GitOpsManager-locked format
        # ``sbom-<YYYY-MM-DD>-<git-short-sha|8>-<scope>``. When no
        # git_sha is available we use a content-derived fingerprint
        # of the SBOM body so multiple scans on the same day with
        # different sources each get a unique id.
        from datetime import datetime, timezone
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        scope = (request.scope or "monorepo") if hasattr(request, "scope") else "monorepo"
        git_sha = getattr(request, "git_sha", None) or sbom_fingerprint[7:15]
        sbom_id = f"sbom-{date}-{git_sha[:8]}-{scope}"

        # Prefix-string source form (``docker:``, ``git:``, ``fs:``,
        # ``lockfile:``) per the v2 wire-format spec.
        source_str = _v1_to_prefix_string(request.source)

        # Format lowercase enum (GitOpsManager convention).
        format_str = request.formats[0].value.lower()

        event_id = await bus.publish(
            f"security.sbom.generated.v1",
            {
                "schema": "security.sbom.generated.v1",
                "sbom_id": sbom_id,
                "source": source_str,
                "format": format_str,
                "component_count": response.components_count,
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "git_sha": git_sha if len(git_sha) == 40 else None,
                "scope": scope,
                # O-3.7-locked fingerprint fields. The runtime is the
                # **producer**; the GitOps auto-committer
                # (``security.yml``) is the **writer** of the sibling
                # ``security/sboms/<sbom_id>/sbom.fingerprint.txt``
                # file. Three fields so future algorithm migrations
                # are forward-compatible (the workflow can recognise
                # the algorithm from the suffix in the fingerprint
                # value, but having the explicit field avoids a
                # parse on every commit).
                "sbom_fingerprint": sbom_fingerprint,
                "sbom_fingerprint_algorithm": "sha256",
                "sbom_fingerprint_format": "cyclonedx-json",
            },
        )
        response.bus_event_id = event_id
    except Exception:  # noqa: BLE001
        # Bus is best-effort; never let publishing break a successful scan.
        pass

    return response


def _v1_to_prefix_string(source: SourceRef) -> str:
    """Translate a v1 ``SourceRef`` to the v2 prefix-string wire form.

    Per the FullstackEngineer + GitOpsManager spec (locked 2026-06-12),
    the four valid prefixes are ``docker:``, ``git:``, ``fs:``,
    ``lockfile:``. We map v1's 7 source kinds to those four:

    * ``docker-image``, ``oci-image``, ``registry``  → ``docker:``
    * ``git-repository``                              → ``git:``
    * ``directory``                                   → ``fs:``
    * ``file``, ``archive``                           → ``fs:`` (or
      ``lockfile:`` for files that end in a known lockfile
      filename — we don't sniff here)
    """
    t = source.type
    if t in (SourceType.DOCKER_IMAGE, SourceType.OCI_IMAGE, SourceType.REGISTRY):
        return f"docker:{source.value}"
    if t is SourceType.GIT_REPOSITORY:
        return f"git:{source.value}"
    if t is SourceType.DIRECTORY:
        return f"fs:{source.value}"
    if t in (SourceType.FILE, SourceType.ARCHIVE):
        return f"fs:{source.value}"
    return f"docker:{source.value}"


# ---------------------------------------------------------------------------
# S2.7 metric helpers
# ---------------------------------------------------------------------------


# Mapping from our v1 SourceType values to the locked S2.7 ``source_type``
# enum. v1 has 7 source kinds; they all funnel to ``syft`` (S2.7 spec)
# because Syft is the scanner that produced the SBOM, and the S2.7
# source_type vocabulary refers to the **scanner**, not the source.
_V1_TO_S2_7_SOURCE_TYPE: Dict[str, str] = {
    "docker-image": MetricsSourceType.SYFT.value,
    "oci-image": MetricsSourceType.SYFT.value,
    "git-repository": MetricsSourceType.SYFT.value,
    "directory": MetricsSourceType.SYFT.value,
    "file": MetricsSourceType.SYFT.value,
    "archive": MetricsSourceType.SYFT.value,
    "registry": MetricsSourceType.SYFT.value,
}


def _s2_7_source_type_for(v1_source_type: str) -> str:
    return _V1_TO_S2_7_SOURCE_TYPE.get(v1_source_type, MetricsSourceType.SYFT.value)


# v1 SourceType values map 1:1 to S2.7 ``target_type`` (the
# source kind being scanned). The locked vocabulary adds
# ``oci-image`` (v1 already had it) and ``archive`` (v1 already
# had it). The other six match by string.
_V1_TO_S2_7_TARGET_TYPE: Dict[str, TargetType] = {
    "docker-image": TargetType.DOCKER,
    "oci-image": TargetType.OCI_IMAGE,
    "git-repository": TargetType.GIT,
    "directory": TargetType.DIRECTORY,
    "file": TargetType.FILE,
    "archive": TargetType.ARCHIVE,
    "registry": TargetType.REGISTRY,
}


def _s2_7_target_type_for(v1_source_type: str) -> TargetType:
    return _V1_TO_S2_7_TARGET_TYPE.get(v1_source_type, TargetType.DIRECTORY)


def _s2_7_repo_shape_for(repo_url: str) -> str:
    """Best-effort repo shape for the ``repo_shape`` label.

    The PlatformArchitect spec (D2 verdict, locked 2026-06-12)
    defines the following vocabulary:

    * ``mono`` — monorepo (multiple services / packages in one
      git tree)
    * ``single`` — single-package repo
    * ``library`` — language library (used as a dependency)
    * ``_unspecified`` — anything we can't classify

    Heuristic: a ``repo_url`` is treated as ``single`` if the path
    has no slash-separated directory components after the
    ``/owner/`` prefix. ``mono`` is the default for full repos
    that don't look like a single-package tree. ``library`` is
    reserved for paths that contain a ``lib/`` segment or
    end with a recognised library naming pattern (``-js``,
    ``-py``, ``-rb``).

    The classifier is intentionally simple — the label is gated
    behind ``target_type="repo"`` so the cardinality cost is
    only paid for git targets.
    """
    if not repo_url or not isinstance(repo_url, str):
        return "_unspecified"
    path = repo_url.split("://", 1)[-1]
    path = path.split(":", 1)[-1]  # strip ssh user@
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if not last:
        return "_unspecified"
    if last.endswith(".git"):
        last = last[:-4]
    if not last:
        return "_unspecified"
    if "/lib/" in path or last.endswith(("-js", "-py", "-rb", "-go", "-rs")):
        return "library"
    # Heuristic: a single-package tree is one whose name is the
    # same as a top-level project name with a single trailing
    # ``-package`` style suffix. Everything else is mono.
    if any(part in path for part in ("/packages/", "/apps/", "/services/")):
        return "mono"
    return "single"


@asynccontextmanager
async def _s2_7_active_scan(telemetry: Any) -> AsyncIterator[None]:
    """Bump ``devsecops_sbom_active_scans`` for the duration of a scan.

    Restored to its previous value (``0``) in the ``finally`` block
    so the gauge correctly reflects "scans in flight right now".
    """
    telemetry.gauge(
        "devsecops_sbom_active_scans",
        value=1.0,
        scanner_type=MetricsSourceType.SYFT.value,
    )
    try:
        yield
    finally:
        telemetry.gauge(
            "devsecops_sbom_active_scans",
            value=0.0,
            scanner_type=MetricsSourceType.SYFT.value,
        )
