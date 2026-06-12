"""SBOM pipeline service — Syft-wrapped SBOM generation, analysis, and storage.

Public package surface (re-exported from submodules):

* :mod:`sbom_pipeline.main` — FastAPI application factory + lifespan
* :mod:`sbom_pipeline.api` — HTTP route handlers
* :mod:`sbom_pipeline.syft_wrapper` — async Syft CLI wrapper
* :mod:`sbom_pipeline.parsers` — CycloneDX/SPDX normalization
* :mod:`sbom_pipeline.analyzer` — SBOM stats (depth, ecosystems, licenses)
* :mod:`sbom_pipeline.store` — SQLite metadata + object-store blobs
* :mod:`sbom_pipeline.bus` — event bus publisher (Sprint 1 EventBus)
* :mod:`sbom_pipeline.telemetry` — OTel + Prometheus instrumentation
* :mod:`sbom_pipeline.models` — Pydantic v2 request/response/DB models
* :mod:`sbom_pipeline.cli` — Click CLI (``python -m sbom_pipeline``)
"""

from __future__ import annotations

from sbom_pipeline.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    Ecosystem,
    ErrorResponse,
    GenerateRequest,
    GenerateResponse,
    HealthResponse,
    ListResponse,
    SBOMFormat,
    SBOMRecord,
    SourceKind,
    parse_source,
)

__version__ = "1.0.0"

__all__ = [
    "AnalyzeRequest",
    "AnalyzeResponse",
    "Ecosystem",
    "ErrorResponse",
    "GenerateRequest",
    "GenerateResponse",
    "HealthResponse",
    "ListResponse",
    "SBOMFormat",
    "SBOMRecord",
    "SourceKind",
    "__version__",
    "parse_source",
]
