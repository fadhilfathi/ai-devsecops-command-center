"""HTTP route handlers.

Endpoints (Lead's locked contract):

* ``POST /sbom/generate``  — generate a new SBOM and persist it
* ``POST /sbom/analyze``   — run the analyzer on a stored SBOM
* ``GET  /sbom/{id}``      — retrieve a stored SBOM
* ``GET  /sbom``           — list SBOMs (paginated)
* ``DELETE /sbom/{id}``    — remove an SBOM
* ``GET  /healthz``        — liveness + syft version
* ``GET  /readyz``         — readiness probe
* ``GET  /metrics``        — Prometheus exposition
* ``POST /bus/respond``    — internal: ack a bus request
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Header,
    HTTPException,
    Path as PathParam,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import ValidationError as PydanticValidationError

from sbom_pipeline.analyzer import analyze
from sbom_pipeline.bus import BusPublisher
from sbom_pipeline.errors import (
    AuthenticationError,
    SBOMError,
    SBOMNotFoundError,
    StorageError,
    SyftNotFoundError,
    ValidationError,
)
from sbom_pipeline.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ErrorResponse,
    GenerateRequest,
    GenerateResponse,
    HealthResponse,
    ListResponse,
    SBOMFormat,
    SBOMRecord,
    parse_source,
    sha256_text,
)
from sbom_pipeline.parsers import (
    cyclonedx_text_to_sbom,
    serialize_sbom,
    syft_to_cyclonedx,
    syft_to_spdx_dict,
)
from sbom_pipeline.syft_wrapper import SyftResult, SyftRunner
from sbom_pipeline.telemetry import Telemetry

logger = logging.getLogger("sbom_pipeline.api")


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_router() -> APIRouter:
    """Build the public APIRouter.

    Dependencies are pulled from ``request.app.state`` so the same
    router is testable against an in-memory DB and a fake Syft runner.
    """
    router = APIRouter()

    # ---- Error handlers attached at app level (see main.py) ----

    # ---- Health / readiness / metrics --------------------------------

    @router.get("/healthz", response_model=HealthResponse, tags=["ops"])
    async def healthz(request: Request) -> HealthResponse:
        state = request.app.state
        syft_version: Optional[str] = None
        try:
            syft_version = await state.syft_runner.warmup()
        except SyftNotFoundError:
            pass
        try:
            bus_ok = await state.bus_publisher.healthy()
        except Exception:  # noqa: BLE001
            bus_ok = False
        repo_ok = await state.repository.healthy()
        uptime = time.time() - state.start_time
        return HealthResponse(
            status="ok" if syft_version else "degraded",
            service=state.settings.service_name,
            version=state.settings.service_version,
            syft_path=state.syft_runner.binary_path,
            syft_version=syft_version,
            db_connected=repo_ok.get("db", False),
            bus_connected=bus_ok,
            uptime_seconds=uptime,
        )

    @router.get("/readyz", tags=["ops"])
    async def readyz(request: Request) -> Response:
        state = request.app.state
        try:
            syft_version = await state.syft_runner.warmup()
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
        repo_ok = await state.repository.healthy()
        if not all(repo_ok.values()):
            return JSONResponse(
                status_code=503,
                content={"status": "unready", "reason": "storage degraded", "details": repo_ok},
            )
        return JSONResponse(content={"status": "ready"})

    @router.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
    async def metrics(request: Request) -> Response:
        state = request.app.state
        body = state.telemetry.render()
        return Response(content=body, media_type=state.telemetry.content_type)

    # ---- Generate ---------------------------------------------------

    @router.post(
        "/sbom/generate",
        response_model=GenerateResponse,
        status_code=status.HTTP_200_OK,
        tags=["sbom"],
    )
    async def generate(
        request: Request,
        body: GenerateRequest,
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
        x_requested_by: Optional[str] = Header(default=None, alias="X-Requested-By"),
    ) -> GenerateResponse:
        return await _generate(
            request,
            body,
            authorization=authorization,
            x_tenant_id=x_tenant_id,
            x_requested_by=x_requested_by,
        )

    # ---- Analyze ----------------------------------------------------

    @router.post(
        "/sbom/analyze",
        response_model=AnalyzeResponse,
        status_code=status.HTTP_200_OK,
        tags=["sbom"],
    )
    async def analyze_sbom(
        request: Request,
        body: AnalyzeRequest,
    ) -> AnalyzeResponse:
        return await _analyze(request, body)

    # ---- Get / List / Delete ---------------------------------------

    @router.get("/sbom/{sbom_id}", tags=["sbom"])
    async def get_sbom(
        request: Request,
        sbom_id: str = PathParam(..., min_length=4, max_length=128),
        format: SBOMFormat = Query(default=SBOMFormat.CYCLONEDX_JSON),
    ) -> Response:
        return await _get_sbom(request, sbom_id, format)

    @router.get("/sbom", response_model=ListResponse, tags=["sbom"])
    async def list_sboms(
        request: Request,
        page: int = Query(default=1, ge=1, le=10_000),
        page_size: int = Query(default=20, ge=1, le=200),
    ) -> ListResponse:
        return await _list_sboms(request, page, page_size)

    @router.delete("/sbom/{sbom_id}", tags=["sbom"])
    async def delete_sbom(
        request: Request,
        sbom_id: str = PathParam(..., min_length=4, max_length=128),
    ) -> Response:
        return await _delete_sbom(request, sbom_id)

    # ---- Internal: bus ack ----------------------------------------

    @router.post("/bus/respond", tags=["bus"], include_in_schema=False)
    async def bus_respond(
        request: Request,
        payload: Dict[str, Any] = Body(...),
    ) -> Dict[str, Any]:
        """Manual hook for replay / testing the bus response path."""
        return {"received": payload, "ack_id": str(uuid.uuid4())}

    return router


# ---------------------------------------------------------------------------
# Handler bodies — separated so tests can call them directly
# ---------------------------------------------------------------------------


async def _generate(
    request: Request,
    body: GenerateRequest,
    *,
    authorization: Optional[str],
    x_tenant_id: Optional[str],
    x_requested_by: Optional[str],
) -> GenerateResponse:
    state = request.app.state
    settings = state.settings
    telemetry: Telemetry = state.telemetry
    runner: SyftRunner = state.syft_runner
    publisher: BusPublisher = state.bus_publisher
    repository = state.repository

    await _check_auth(settings, authorization, x_tenant_id)

    parsed = parse_source(body.source)
    start = time.time()
    telemetry.set_active_scans(
        telemetry.get_active_scans("syft") + 1,
        scanner_type="syft",
    )
    try:
        # ---- Run Syft
        syft_result = await runner.scan(
            parsed=parsed,
            fmt=body.format,
            timeout=settings.request_timeout_seconds,
        )

        # ---- Normalize to wire model
        if body.format in (SBOMFormat.SPDX_JSON, SBOMFormat.SPDX_TAG_VALUE):
            # For SPDX outputs we still want the analyzer to see
            # CycloneDX-style components, so we run the CycloneDX
            # path AND serialize SPDX for the response body.
            sbom = syft_to_cyclonedx(syft_result.raw)
            body_text, media_type = serialize_sbom(sbom, body.format)
            data_obj: Dict[str, Any] = {"spdx": json.loads(body_text) if body.format == SBOMFormat.SPDX_JSON else {"raw": body_text}}
        elif body.format == SBOMFormat.SYFT_JSON:
            data_obj = syft_result.raw
            sbom = syft_to_cyclonedx(syft_result.raw)
            body_text, media_type = json.dumps(data_obj), "application/json"
        else:
            sbom = syft_to_cyclonedx(syft_result.raw)
            body_text, media_type = serialize_sbom(sbom, body.format)
            data_obj = json.loads(body_text)

        # ---- Persist
        # Use a content fingerprint when no git_sha is given, so
        # multiple scans of different sources on the same day each
        # get a unique sbom_id (otherwise the UNIQUE constraint on
        # sboms.id would reject the second one).
        record_id = SBOMRecord.make_id(
            scope=body.scope or "monorepo",
            git_sha=body.git_sha,
            source_fingerprint=(
                None
                if body.git_sha
                else sha256_text(body_text)[:8]
            ),
        )
        size_bytes = len(body_text.encode("utf-8"))
        record = SBOMRecord(
            id=record_id,
            source=body.source,
            format=body.format,
            data_json=body_text,
            created_at=datetime.now(timezone.utc),
            sha256=sha256_text(body_text),
            size_bytes=size_bytes,
            component_count=len(sbom.components),
            scope=body.scope,
            git_sha=body.git_sha,
        )
        # Insert metadata, then write the raw blob to the object store.
        await repository.db.insert(record)
        await repository.objects.put(
            f"{record.id}.{_ext_for(body.format)}",
            body_text.encode("utf-8"),
        )
        await publisher.publish_event(
            f"{settings.bus_subject_prefix}.stored.v1",
            {
                "sbom_id": record.id,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "stored_at": record.created_at.isoformat(),
            },
        )

        # ---- Auto-analyze + emit
        analysis = analyze(sbom)
        await publisher.publish_event(
            f"{settings.bus_subject_prefix}.analyzed.v1",
            {
                "sbom_id": record.id,
                **analysis,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        # ---- Emit the main "generated" event
        await publisher.publish_event(
            f"{settings.bus_subject_prefix}.generated.v1",
            {
                "sbom_id": record.id,
                "source": body.source,
                "format": body.format.value,
                "component_count": record.component_count,
                "generated_at": record.created_at.isoformat(),
                "git_sha": body.git_sha,
                "scope": body.scope or "monorepo",
            },
        )

        duration = time.time() - start
        telemetry.record_job(
            result="success",
            source_type=parsed.kind.value,
            duration_seconds=duration,
            fmt=body.format.value,
            ecosystem=syft_result.dominant_ecosystem,
            components=record.component_count,
        )

        return GenerateResponse(
            sbom_id=record.id,
            format=body.format,
            data=data_obj,
            component_count=record.component_count,
            size_bytes=size_bytes,
            sha256=record.sha256,
            created_at=record.created_at,
            warnings=syft_result.warnings,
        )

    except SBOMError:
        duration = time.time() - start
        telemetry.record_job(
            result="failed",
            source_type=parsed.kind.value,
            duration_seconds=duration,
            fmt=body.format.value,
            ecosystem="unknown",
            components=0,
        )
        await publisher.publish_event(
            f"{settings.bus_subject_prefix}.failed.v1",
            {
                "source": body.source,
                "error": "scan failed",
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "requested_by": x_requested_by,
            },
        )
        raise
    except Exception as exc:  # noqa: BLE001
        duration = time.time() - start
        telemetry.record_job(
            result="failed",
            source_type=parsed.kind.value,
            duration_seconds=duration,
            fmt=body.format.value,
            ecosystem="unknown",
            components=0,
        )
        await publisher.publish_event(
            f"{settings.bus_subject_prefix}.failed.v1",
            {
                "source": body.source,
                "error": str(exc),
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "requested_by": x_requested_by,
            },
        )
        raise
    finally:
        # Re-read the gauge value (avoid clobbering concurrent updates).
        try:
            current = telemetry.get_active_scans("syft")
            telemetry.set_active_scans(max(0, current - 1), scanner_type="syft")
        except Exception:  # noqa: BLE001
            pass


async def _analyze(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    repository = request.app.state.repository
    publisher: BusPublisher = request.app.state.bus_publisher
    record = await repository.db.get(body.sbom_id)
    sbom = cyclonedx_text_to_sbom(record.data_json)
    stats = analyze(sbom)
    return AnalyzeResponse(
        sbom_id=body.sbom_id,
        analyzed_at=datetime.now(timezone.utc),
        **stats,
    )


async def _get_sbom(
    request: Request, sbom_id: str, fmt: SBOMFormat
) -> Response:
    repository = request.app.state.repository
    record = await repository.db.get(sbom_id)
    if fmt == SBOMFormat.CYCLONEDX_JSON:
        return Response(
            content=record.data_json,
            media_type="application/vnd.cyclonedx+json",
        )
    # Re-serialize the stored SBOM into the requested format.
    sbom = cyclonedx_text_to_sbom(record.data_json)
    body, media_type = serialize_sbom(sbom, fmt)
    return Response(content=body, media_type=media_type)


async def _list_sboms(request: Request, page: int, page_size: int) -> ListResponse:
    repository = request.app.state.repository
    items, total = await repository.db.list(page=page, page_size=page_size)
    return ListResponse(items=items, page=page, page_size=page_size, total=total)


async def _delete_sbom(request: Request, sbom_id: str) -> Response:
    repository = request.app.state.repository
    deleted = await repository.db.delete(sbom_id)
    if not deleted:
        raise SBOMNotFoundError(
            f"sbom {sbom_id!r} not found", details={"sbom_id": sbom_id}
        )
    # Best-effort blob cleanup.
    try:
        await repository.objects.delete(f"{sbom_id}.cyclonedx.json")
    except Exception:  # noqa: BLE001
        pass
    return JSONResponse(content={"deleted": True, "sbom_id": sbom_id})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _check_auth(
    settings, authorization: Optional[str], x_tenant_id: Optional[str]
) -> None:
    if not settings.require_auth:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthenticationError("missing or malformed bearer token")
    if not x_tenant_id:
        raise AuthenticationError("X-Tenant-Id header required when auth is enabled")


def _ext_for(fmt: SBOMFormat) -> str:
    return {
        SBOMFormat.CYCLONEDX_JSON: "cyclonedx.json",
        SBOMFormat.CYCLONEDX_XML: "cyclonedx.xml",
        SBOMFormat.SPDX_JSON: "spdx.json",
        SBOMFormat.SPDX_TAG_VALUE: "spdx.spdx",
        SBOMFormat.SYFT_JSON: "syft.json",
    }[fmt]
