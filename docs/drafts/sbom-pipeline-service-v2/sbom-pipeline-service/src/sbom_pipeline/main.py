"""FastAPI application factory + lifespan.

This module is the composition root — it wires every other piece
together:

* :class:`Settings` loaded from env
* :class:`Telemetry` (OTel + Prometheus)
* :class:`SyftRunner` (CLI wrapper)
* :class:`BusPublisher` (event bus)
* :class:`SBOMRepository` (SQLite + object store)

The :func:`create_app` factory takes an explicit :class:`Settings`
so tests can override any value without monkey-patching modules.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from sbom_pipeline.api import build_router
from sbom_pipeline.bus import BusPublisher, build_bus
from sbom_pipeline.config import Settings
from sbom_pipeline.errors import SBOMError
from sbom_pipeline.models import ErrorResponse
from sbom_pipeline.store import (
    ObjectStore,
    SBOMRepository,
    SBOMStore,
)
from sbom_pipeline.syft_wrapper import SyftRunner
from sbom_pipeline.telemetry import build_telemetry

logger = logging.getLogger("sbom_pipeline.main")


def _sanitize_validation_errors(errors: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Coerce Pydantic ``ValidationError.errors()`` output to JSON.

    Pydantic v2 includes the original ``ValueError`` instance (or any
    other exception) in the ``ctx`` field of a validation error when
    a field validator raised it explicitly. The default encoder in
    FastAPI's :class:`JSONResponse` will refuse to serialise that —
    we get a ``TypeError: Object of type ValueError is not JSON
    serializable`` when the response is rendered. We strip non-primitive
    values from ``ctx`` here.
    """
    out: list[Dict[str, Any]] = []
    for err in errors:
        cleaned: Dict[str, Any] = {}
        for k, v in err.items():
            if k == "ctx" and isinstance(v, dict):
                cleaned[k] = {ck: str(cv) for ck, cv in v.items()}
            elif k == "input" and isinstance(v, (bytes, bytearray)):
                cleaned[k] = f"<{len(v)} bytes>"
            else:
                cleaned[k] = v
        out.append(cleaned)
    return out


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    telemetry = app.state.telemetry
    repository = app.state.repository
    bus_publisher = app.state.bus_publisher
    syft_runner = app.state.syft_runner

    # Connect storage
    try:
        await repository.db.connect()
        kind, path = settings.object_store_parsed()
        repository.objects = ObjectStore(
            "s3://" + path if kind == "s3" else path
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("storage connect failed: %s", exc)
        # Continue — /readyz will surface the failure.

    # Connect bus
    try:
        await bus_publisher.connect()
    except Exception as exc:  # noqa: BLE001
        logger.error("bus connect failed: %s", exc)

    # Warm Syft version cache
    try:
        await syft_runner.warmup()
    except Exception as exc:  # noqa: BLE001
        logger.error("syft warmup failed: %s", exc)

    # Subscribe to inbound bus requests (best-effort).
    try:
        await bus_publisher.bus.subscribe(
            settings.bus_requested_subject, _on_bus_request(app)
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("bus subscribe failed: %s", exc)

    logger.info(
        "sbom-pipeline ready on %s:%d (syft=%s, bus=%s)",
        settings.host,
        settings.port,
        syft_runner.binary_path,
        settings.bus_url,
    )

    try:
        yield
    finally:
        # Best-effort teardown — never raise from shutdown.
        try:
            await bus_publisher.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            await repository.db.disconnect()
        except Exception:  # noqa: BLE001
            pass


def _on_bus_request(app: FastAPI):
    """Build the bus-request handler closure.

    The handler defers to the HTTP path so we don't duplicate
    business logic across two entry points.
    """
    async def handler(payload: Dict[str, Any]) -> None:
        try:
            # Translate a bus request to a GenerateRequest and run it.
            from sbom_pipeline.models import GenerateRequest
            from sbom_pipeline.api import _generate

            req = GenerateRequest.model_validate(payload)
            fake_request = _fake_request(app, req)
            await _generate(
                fake_request,
                req,
                authorization=None,
                x_tenant_id=payload.get("tenant_id"),
                x_requested_by=payload.get("requested_by"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("bus request failed: %s", exc)

    return handler


def _fake_request(app: FastAPI, body: Any) -> Request:
    """Build a minimal Request object for the bus path.

    We only use ``request.app.state`` inside the handler, so the
    rest of the Request surface can be a stand-in.
    """
    scope = {"type": "http", "app": app, "headers": []}

    class _Stub:
        pass

    stub = _Stub()
    stub.app = app
    return stub  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Application factory — every dependency is wired here."""
    settings = settings or Settings()

    telemetry = build_telemetry(settings.service_name)
    bus = build_bus(settings.bus_url)
    publisher = BusPublisher(bus=bus, service=settings.service_name)
    semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
    syft_runner = SyftRunner(binary=settings.syft_binary, semaphore=semaphore)

    # Storage (deferred connect in lifespan).
    kind, path = settings.object_store_parsed()
    db = SBOMStore(settings.db_url)
    objects = ObjectStore("s3://" + path if kind == "s3" else path)
    repository = SBOMRepository(db=db, objects=objects)

    app = FastAPI(
        title="AionRs SBOM Pipeline",
        version=settings.service_version,
        description=(
            "Syft-wrapped SBOM generation, analysis, and storage "
            "service. Produces CycloneDX 1.5 and SPDX 2.3 from "
            "Docker images, git repos, filesystems, and lockfiles."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.telemetry = telemetry
    app.state.bus = bus
    app.state.bus_publisher = publisher
    app.state.syft_runner = syft_runner
    app.state.repository = repository
    app.state.start_time = time.time()

    # ---- Error handlers -------------------------------------------

    @app.exception_handler(SBOMError)
    async def _sbom_error_handler(_: Request, exc: SBOMError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.http_status,
            content=ErrorResponse(
                code=exc.code, message=exc.message, details=exc.details
            ).model_dump(),
        )

    @app.exception_handler(PydanticValidationError)
    async def _pydantic_error_handler(
        _: Request, exc: PydanticValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                code="validation_error",
                message="Request payload failed validation",
                details={"errors": _sanitize_validation_errors(exc.errors())},
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def _request_error_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                code="validation_error",
                message="Request payload failed validation",
                details={"errors": _sanitize_validation_errors(exc.errors())},
            ).model_dump(),
        )

    # ---- Routes ----------------------------------------------------

    app.include_router(build_router())

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> int:
    """``python -m sbom_pipeline.main`` entrypoint."""
    import uvicorn

    settings = Settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    app = create_app(settings=settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
