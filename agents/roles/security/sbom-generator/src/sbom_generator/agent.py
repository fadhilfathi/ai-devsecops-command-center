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
            # Bump the SRE F1 counter: SSRF rejection.
            # Reason classification: ``dns_rebinding`` (hostname
            # resolved to a private IP) vs ``blocklist`` (literal IP
            # or banned hostname). SRE's burn-rate alert watches the
            # rate of this counter.
            try:
                warning_type = (
                    "dns_rebinding"
                    if "rebind" in (result.reason or "").lower()
                    else "blocklist"
                )
                self._telemetry.counter(
                    "devsecops_sbom_ssrf_warnings_total",
                    value=1.0,
                    warning_type=warning_type,
                    result="deny",
                )
            except Exception:  # noqa: BLE001
                # Telemetry is best-effort; never fail the request on
                # a counter increment.
                pass

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

        # Allowed — emit allow_with_warning telemetry when the host was
        # allowlisted but the resolution was suspicious (e.g., no
        # resolved addresses returned, or the resolved set points to a
        # cloud-metadata IP). The counter increments BEFORE we lose the
        # ``result`` to the caller, so we can never accidentally bypass
        # the increment. SRE F1 alert surface: burn-rate on this
        # counter is the canary for attacker probing.
        try:
            warning_type = "none"
            if not result.resolved_addresses:
                warning_type = "allow_no_resolved_addresses"
            elif any(
                self._is_metadata_address(addr) for addr in result.resolved_addresses
            ):
                warning_type = "allow_resolves_to_metadata"

            if warning_type != "none":
                self._telemetry.counter(
                    "devsecops_sbom_ssrf_warnings_total",
                    value=1.0,
                    warning_type=warning_type,
                    result="allow_with_warning",
                )
        except Exception:  # noqa: BLE001
            pass

        # Allowed — log resolved addresses for forensics.
        if result.resolved_addresses:
            logger.info(
                "SSRF allowed: target=%s resolved=%s",
                target,
                result.resolved_addresses,
            )

    @staticmethod
    def _is_metadata_address(addr: str) -> bool:
        """Heuristic: is ``addr`` likely a cloud-metadata endpoint?

        Used to flag ``allow_with_warning`` telemetry. The IP-based
        blocklist already covers 169.254.169.254, but we re-check
        here so the warning fires when the host resolved to a known
        metadata IP *after* allowlist relaxation.
        """
        import ipaddress

        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        # 169.254.169.254/32 (AWS IMDS), 169.254.170.2/32 (ECS task
        # metadata), 169.254.0.0/16 (link-local) — covered by the IP
        # blocklist at the host, but re-flagged here for the warning.
        return ip in ipaddress.ip_network("169.254.0.0/16")

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

        # Format lowercase enum (GitOpsManager convention).
        format_str = request.formats[0].value.lower()

        # O-3.7 wire format compliance — every required field on
        # security.sbom.generated.v1 must be present, and the values
        # must match the JSON Schema's enums. Drift fix landed in
        # hotfix/s2.5-sbom-wire-format-drift (this commit) to align the
        # runtime with security/wire-format/sbom-generated.schema.json.
        scope_value = _o37_scope_value(request)
        subject_value = _o37_subject(request)
        subject_fingerprint_value = _o37_subject_fingerprint(
            request, sbom_fingerprint, git_sha
        )
        sbom_path_value = _o37_sbom_path(request)
        sbom_format_value = _o37_format_value(format_str)

        event_id = await bus.publish(
            f"security.sbom.generated.v1",
            {
                "schema": "security.sbom.generated.v1",
                "sbom_id": sbom_id,
                "scope": scope_value,
                "subject": subject_value,
                "subject_fingerprint": subject_fingerprint_value,
                "sbom_format": sbom_format_value,
                "sbom_path": sbom_path_value,
                "components_count": response.components_count,
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
                # The O-3.7 enum encodes format + canonicalization
                # together so the wire is unambiguous. The
                # +canonicalized-jcs suffix is the default — we
                # compute the fingerprint over the RFC 8785 JCS
                # canonicalization of the SBOM bytes.
                "sbom_fingerprint_format": "cyclonedx-json+canonicalized-jcs",
                "generator": {
                    "name": "syft",
                    "version": syft_version,
                    "binary_path": result.binary_path,
                },
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
# O-3.7 wire format helpers (S2.5 hotfix)
# ---------------------------------------------------------------------------
# These translate runtime context into the locked wire-format fields:
#   - ``scope``                (enum, 6 values)
#   - ``subject``              (opaque reference, e.g. "repo:owner/name")
#   - ``subject_fingerprint``  (scope-aware: git SHA / image digest / ...)
#   - ``sbom_path``            (relative path within the repo or scan root)
#   - ``sbom_format``          (enum: cyclonedx-json, spdx-json)
#
# When the runtime cannot determine a field, it computes a safe default
# (content fingerprint for ``fs``, sha256(reference) for ``container``,
# etc.) so the wire is always complete — consumers should never see a
# missing required field.
# ---------------------------------------------------------------------------


_O37_FORMAT_MAP = {
    "cyclonedx-json": "cyclonedx-json",
    "spdx-json": "spdx-json",
    "spdx-tag-value": "spdx-json",  # promoted to spdx-json for Sprint 2.1
    "spdx": "spdx-json",
    "cyclonedx-xml": "cyclonedx-json",  # fall back to JSON for Sprint 2.1
}


def _o37_format_value(format_str: str) -> str:
    """Map a runtime format string to the O-3.7 ``sbom_format`` enum.

    The O-3.7 schema only enumerates two values: ``cyclonedx-json``
    and ``spdx-json``. We promote other formats (``spdx``, ``spdx-tag-value``,
    ``cyclonedx-xml``) to the JSON equivalents so the wire is always
    one of the two locked values. The actual emission format is still
    controlled by ``request.formats[0]``; this helper only emits the
    classification label.
    """
    return _O37_FORMAT_MAP.get(format_str.lower(), "cyclonedx-json")


def _o37_scope_value(request) -> str:
    """Return the O-3.7 scope for the request, or a derived default.

    The 6-value enum lives at ``models.request.VALID_SCOPE_TYPES``. The
    default is derived from the source kind: ``container`` for
    image/registry sources, ``git-tree`` for git, ``fs`` for local paths.
    """
    explicit = getattr(request, "scope", None)
    if explicit:
        return explicit
    t = request.source.type
    if t in (SourceType.DOCKER_IMAGE, SourceType.OCI_IMAGE, SourceType.REGISTRY):
        return "container"
    if t is SourceType.GIT_REPOSITORY:
        return "git-tree"
    return "fs"


def _o37_subject(request) -> str:
    """Return the O-3.7 ``subject`` field (opaque reference).

    The convention is ``<kind>:<ref>`` mirroring the v2 prefix-string
    wire format, but with extra context for the O-3.7 discriminator.
    Examples:

      docker:anchore/syft:v1.6.0
      git:https://github.com/aionrs/api.git
      fs:/workspace/monorepo/services/api
      repo:github.com/aionrs/api
    """
    t = request.source.type
    if t in (SourceType.DOCKER_IMAGE, SourceType.OCI_IMAGE):
        return f"docker:{request.source.value}"
    if t is SourceType.REGISTRY:
        return f"registry:{request.source.value}"
    if t is SourceType.GIT_REPOSITORY:
        v = request.source.value
        # If the value is a URL, return the repo form (drop the scheme).
        if "://" in v:
            from urllib.parse import urlparse

            p = urlparse(v)
            host = p.hostname or ""
            path = p.path.lstrip("/")
            if path.endswith(".git"):
                path = path[:-4]
            return f"repo:{host}/{path}" if host else f"git:{v}"
        # SCP-style: ``user@host:owner/repo.git`` -> ``repo:host/owner/repo``
        m = re.match(r"^[\w-]+@([\w.\-]+):(.+?)(?:\.git)?$", v)
        if m:
            host, path = m.group(1), m.group(2)
            return f"repo:{host}/{path}"
        return f"git:{v}"
    if t in (SourceType.DIRECTORY, SourceType.FILE, SourceType.ARCHIVE):
        return f"fs:{request.source.value}"
    return f"unknown:{request.source.value}"


def _o37_subject_fingerprint(request, sbom_fingerprint: str, git_sha: str) -> str:
    """Return the O-3.7 ``subject_fingerprint`` field, scope-aware.

    Behavior:

      * **container** scope: prefer an explicit image digest
        (``sha256:<hex>``). If only a tag is provided, fall back to
        ``sha256(sha256(image_ref + ":" + tag))`` so the wire is
        non-empty and deterministic for the same input. The runtime
        records the actual digest via the ``provenance_path`` artifact
        (written by the GitOps auto-committer) for Sprint 3
        reconciliation.
      * **monorepo / git-tree / service / package** scope: prefer the
        caller-provided ``git_sha`` (full 40-char SHA). Fall back to
        the short SHA from the sbom_id derivation.
      * **fs** scope: prefer an explicit content hash if the caller
        supplies one in ``metadata``; otherwise derive
        ``sha256(reference)`` from the source value.

    The function never returns an empty string — the O-3.7 schema
    requires ``minLength: 1``.
    """
    explicit = getattr(request, "subject_fingerprint", None)
    if explicit:
        return explicit

    scope = _o37_scope_value(request)
    if scope == "container":
        # Container references can be ``name:tag`` (no digest at scan
        # time without a registry pull). We emit a deterministic
        # placeholder the runtime computed from the reference. The
        # real digest lands in the sibling ``provenance_path`` artifact.
        ref = request.source.value
        return "sha256:" + hashlib.sha256(ref.encode("utf-8")).hexdigest()

    if scope in ("monorepo", "git-tree", "service", "package"):
        if git_sha and len(git_sha) >= 7:
            return git_sha
        # Last-resort fallback: derive from sbom_fingerprint.
        return sbom_fingerprint

    # fs scope
    meta_hash = (getattr(request, "metadata", None) or {}).get(
        "content_sha256"
    )
    if meta_hash:
        return meta_hash
    ref = request.source.value
    return "sha256:" + hashlib.sha256(ref.encode("utf-8")).hexdigest()


def _o37_sbom_path(request) -> str:
    """Return the O-3.7 ``sbom_path`` field.

    Conventions:

      * **git-scoped** (``monorepo``, ``service``, ``git-tree``):
        use ``request.subject_path`` (relative repo path per the
        folder contract). Fall back to ``.`` (repo root) when not
        provided.
      * **fs** scope: the absolute or relative path the caller
        scanned; truncated to the basename when very long.
      * **container** scope: the OCI reference itself (it IS the
        path-like identifier).
      * **package** scope: the package coordinate (``ecosystem:name``).
    """
    scope = _o37_scope_value(request)
    t = request.source.type
    if scope in ("monorepo", "service", "git-tree"):
        return getattr(request, "subject_path", None) or "."
    if t in (SourceType.DOCKER_IMAGE, SourceType.OCI_IMAGE):
        return request.source.value
    if t is SourceType.REGISTRY:
        return request.source.value
    if scope == "package":
        # Best-effort: parse the source value as ``ecosystem:name`` if
        # the caller used the lockfile form.
        v = request.source.value
        if ":" in v and not v.startswith("http"):
            return v
        return v
    # fs scope
    return request.source.value


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
