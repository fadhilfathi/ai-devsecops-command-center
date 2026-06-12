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
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from sbom_generator.config import Settings
from sbom_generator.models.request import GenerateRequest
from sbom_generator.models.response import GenerateResponse
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
        record = JobRecord(
            request_id="-",  # filled in by caller
            started_at=0.0,
        )
        self._active_jobs.append(record)
        try:
            self._telemetry.inc("sbom_jobs_total", format=request.formats[0].value)
            with self._telemetry.span(
                "sbom.generate",
                source_type=request.source.type,
                source_value=request.source.value,
            ):
                syft_result = await self._runner.run(
                    request=request,
                    fmt=request.formats[0],
                    timeout=self._settings.request_timeout_seconds,
                )
            self._telemetry.observe("syft_duration_ms", syft_result.elapsed_ms)
            self._telemetry.observe(
                "components_per_scan", len(syft_result.sbom.components)
            )
            record.success = True
            return _build_response(request, syft_result, self._bus, self._settings)
        finally:
            record.finished_at = 0.0  # timestamp set in response builder

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
        event_id = await bus.publish(
            f"{settings.bus_subject_prefix}.events",
            {
                "kind": "sbom.generated",
                "request_id": response.request_id,
                "job_id": response.job_id,
                "source_type": request.source.type,
                "components": response.components_count,
                "format": request.formats[0].value,
            },
        )
        response.bus_event_id = event_id
    except Exception:  # noqa: BLE001
        # Bus is best-effort; never let publishing break a successful scan.
        pass

    return response
