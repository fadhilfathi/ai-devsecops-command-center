"""FastAPI application factory for the SBOM generator service.

The service exposes a small, focused HTTP surface:

* ``GET  /healthz``             — liveness + syft version + bus status
* ``GET  /readyz``              — readiness probe (bus connected, syft found)
* ``GET  /metrics``             — Prometheus exposition
* ``POST /v1/sbom/generate``    — generate a single SBOM
* ``POST /v1/sbom/analyze``     — alias of ``/generate`` (compat with
                                  the security-service API contract)
* ``GET  /v1/sbom/formats``     — list supported output formats
* ``GET  /v1/sbom/source-kinds``— list supported source types
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import (
    Body,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError as PydanticValidationError

from sbom_generator.agent import (
    BusClient,
    InMemoryBus,
    NATSClient,
    SBOMGeneratorAgent,
)
from sbom_generator.config import Settings
from sbom_generator.errors import (
    AuthenticationError,
    PermissionDeniedError,
    SBOMError,
    SyftNotFoundError,
    ValidationError,
)
from sbom_generator.models.request import (
    VALID_SOURCE_TYPES,
    GenerateRequest,
    SourceType,
)
from sbom_generator.models.response import (
    ErrorResponse,
    GenerateResponse,
    HealthResponse,
)
from sbom_generator.models.sbom import SBOMFormat
from sbom_generator.syft import SyftRunner
from sbom_generator.telemetry import Telemetry

logger = logging.getLogger("sbom_generator.service")


def _build_bus(settings: Settings) -> BusClient:
    if not settings.bus_url or settings.bus_url.startswith("memory://"):
        return InMemoryBus()
    return NATSClient(settings.bus_url)


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Application factory — every dependency is wired here."""
    settings = settings or Settings.from_env()
    bus = _build_bus(settings)
    telemetry = Telemetry(service_name=settings.service_name)
    semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
    runner = SyftRunner(binary=settings.syft_binary, semaphore=semaphore)
    agent = SBOMGeneratorAgent(
        settings=settings,
        runner=runner,
        bus=bus,
        telemetry=telemetry,
    )

    app = FastAPI(
        title="AionRs SBOM Generator",
        version="1.0.0",
        description=(
            "Syft-wrapped SBOM generation service. Produces CycloneDX "
            "(JSON/XML) and SPDX (JSON/tag-value) for Docker images, "
            "git repos, filesystems, and language lockfiles."
        ),
    )
    app.state.settings = settings
    app.state.bus = bus
    app.state.telemetry = telemetry
    app.state.runner = runner
    app.state.agent = agent
    app.state.start_time = time.time()

    # ---- Error handlers ------------------------------------------------

    @app.exception_handler(SBOMError)
    async def _sbom_error_handler(_: Request, exc: SBOMError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content=ErrorResponse(
                code=exc.code, message=exc.message, details=exc.details
            ).model_dump(),
        )

    @app.exception_handler(PydanticValidationError)
    async def _validation_error_handler(
        _: Request, exc: PydanticValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                code="validation_error",
                message="Request payload failed validation",
                details={"errors": exc.errors()},
            ).model_dump(),
        )

    # ---- Auth ---------------------------------------------------------

    async def _check_auth(
        authorization: Optional[str],
        tenant_id: Optional[str],
    ) -> None:
        if not settings.require_auth:
            return
        if not authorization or not authorization.lower().startswith("bearer "):
            raise AuthenticationError("missing or malformed bearer token")
        if not tenant_id:
            raise AuthenticationError(
                "tenant id header required when auth is enabled",
                details={"header": settings.tenant_header},
            )

    # ---- Lifecycle ----------------------------------------------------

    @app.on_event("startup")
    async def _startup() -> None:
        try:
            await agent.start()
            app.state.start_time = time.time()
        except SyftNotFoundError as exc:
            logger.error("syft not found on startup: %s", exc)
            # We still want /healthz to surface the problem instead of
            # crashing the whole process.
        except Exception as exc:  # noqa: BLE001
            logger.exception("startup failed: %s", exc)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await agent.stop()

    # ---- Health & metrics ---------------------------------------------

    @app.get("/healthz", response_model=HealthResponse, tags=["ops"])
    async def healthz(request: Request) -> HealthResponse:
        state_runner = request.app.state.runner
        state_bus = request.app.state.bus
        syft_version: Optional[str] = None
        try:
            syft_version = await state_runner.warmup()
        except SyftNotFoundError:
            pass
        bus_ok = False
        try:
            bus_ok = await state_bus.healthy()
        except Exception:  # noqa: BLE001
            bus_ok = False
        uptime = time.time() - app.state.start_time
        checks: Dict[str, Dict[str, Any]] = {
            "syft": {
                "path": state_runner.binary_path,
                "version": syft_version,
                "ok": syft_version is not None,
            },
            "bus": {
                "connected": bus_ok,
                "ok": bus_ok,
            },
        }
        return HealthResponse(
            status="ok" if syft_version else "degraded",
            service=settings.service_name,
            version="1.0.0",
            syft_path=state_runner.binary_path,
            syft_version=syft_version,
            uptime_seconds=uptime,
            bus_connected=bus_ok,
            active_jobs=agent.active_job_count,
            max_concurrent_jobs=settings.max_concurrent_scans,
            checks=checks,
        )

    @app.get("/readyz", tags=["ops"])
    async def readyz(request: Request) -> Response:
        state_runner = request.app.state.runner
        try:
            syft_version = await state_runner.warmup()
        except SyftNotFoundError as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "unready", "reason": str(exc)},
            )
        if syft_version is None:
            return JSONResponse(
                status_code=503,
                content={"status": "unready", "reason": "syft version probe failed"},
            )
        return JSONResponse(content={"status": "ready"})

    @app.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
    async def metrics(request: Request) -> Response:
        state_telemetry = request.app.state.telemetry
        body = state_telemetry.render_prometheus()
        return Response(content=body, media_type="text/plain; version=0.0.4")

    # ---- Discovery ----------------------------------------------------

    @app.get("/v1/sbom/formats", tags=["discovery"])
    async def list_formats() -> Dict[str, Any]:
        from sbom_generator.output import get_media_type

        return {
            "formats": [
                {
                    "id": f.value,
                    "media_type": get_media_type(f),
                    "spec": {
                        SBOMFormat.CYCLONEDX_JSON.value: "CycloneDX 1.5 (JSON)",
                        SBOMFormat.CYCLONEDX_XML.value: "CycloneDX 1.5 (XML)",
                        SBOMFormat.SPDX_JSON.value: "SPDX 2.3 (JSON)",
                        SBOMFormat.SPDX_TAG_VALUE.value: "SPDX 2.3 (tag:value)",
                        SBOMFormat.SYFT_JSON.value: "Syft native JSON",
                    }[f.value],
                }
                for f in SBOMFormat
            ],
        }

    @app.get("/v1/sbom/source-kinds", tags=["discovery"])
    async def list_source_kinds() -> Dict[str, Any]:
        descriptions = {
            SourceType.DIRECTORY: "Local filesystem directory (recursive).",
            SourceType.FILE: "Single file on the local filesystem.",
            SourceType.DOCKER_IMAGE: "Container image reference (e.g. nginx:1.25).",
            SourceType.OCI_IMAGE: "OCI image in a registry, fetched by digest.",
            SourceType.GIT_REPOSITORY: "Git repository URL (https/git/ssh/file).",
            SourceType.ARCHIVE: "Tarball / zip archive (local or remote).",
            SourceType.REGISTRY: "Enumerate a registry catalog (https URL).",
        }
        return {
            "source_kinds": [
                {"id": kind, "description": descriptions.get(kind, "")}
                for kind in sorted(VALID_SOURCE_TYPES)
            ]
        }

    # ---- Generate -----------------------------------------------------

    @app.post(
        "/v1/sbom/generate",
        response_model=GenerateResponse,
        tags=["sbom"],
        status_code=status.HTTP_200_OK,
    )
    async def generate(
        request: GenerateRequest,
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
    ) -> GenerateResponse:
        await _check_auth(authorization, tenant_id)
        if tenant_id and not request.tenant_id:
            request.tenant_id = tenant_id
        try:
            return await agent.generate(request)
        except SBOMError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("unexpected error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post(
        "/v1/sbom/analyze",
        response_model=GenerateResponse,
        tags=["sbom"],
        status_code=status.HTTP_200_OK,
    )
    async def analyze(
        request: GenerateRequest,
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
    ) -> GenerateResponse:
        """Compatibility alias — same as ``/v1/sbom/generate``.

        The platform's security-service routes ``/sbom/analyze`` to this
        agent. We accept the same body shape.
        """
        return await generate(request, authorization=authorization, tenant_id=tenant_id)

    @app.post(
        "/v1/sbom/quick",
        tags=["sbom"],
        response_model=GenerateResponse,
        status_code=status.HTTP_200_OK,
    )
    async def quick_generate(
        payload: Dict[str, Any] = Body(
            ...,
            example={
                "source": "nginx:1.25",
                "format": "cyclonedx-json",
            },
        ),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
    ) -> GenerateResponse:
        """Simplified ``{source, format}`` payload for ad-hoc scans.

        Used by ops scripts and CLI utilities. The full
        :class:`GenerateRequest` payload remains the canonical
        interface.
        """
        await _check_auth(authorization, tenant_id)
        source_value = payload.get("source")
        if not source_value or not isinstance(source_value, str):
            raise ValidationError("payload.source must be a non-empty string")
        fmt_raw = payload.get("format", "cyclonedx-json")
        try:
            fmt = SBOMFormat(fmt_raw)
        except ValueError as exc:
            raise ValidationError(
                f"unsupported format={fmt_raw!r}",
                details={"valid": [f.value for f in SBOMFormat]},
            ) from exc
        inferred = _infer_source_kind(source_value)
        request = GenerateRequest(
            source={"type": inferred, "value": source_value},
            formats=[fmt],
            tenant_id=tenant_id,
        )
        return await agent.generate(request)

    return app


def _infer_source_kind(value: str) -> str:
    """Heuristic source-kind detection for the quick endpoint."""
    if value.startswith(("https://", "git@", "git://", "ssh://", "file://")):
        return SourceType.GIT_REPOSITORY
    if value.startswith("registry:"):
        return SourceType.REGISTRY
    if value.endswith(
        (".tar", ".tar.gz", ".tgz", ".zip", ".tar.xz", ".tar.bz2")
    ):
        return SourceType.ARCHIVE
    if ":" in value or "@sha256:" in value or value.startswith("oci://"):
        if "/" in value or ":" in value:
            return SourceType.DOCKER_IMAGE
    if value.startswith(("./", "/", "~")) or value in (".", ".."):
        return SourceType.DIRECTORY
    return SourceType.DOCKER_IMAGE
