"""FastAPI app factory for vuln-intel.

This module wires the data sources, store, cache, enrichment clients
and routing. It deliberately keeps the wiring explicit so the same
``Service`` class can be reused in tests (and consumed from a future
NATS / Redis bridge without FastAPI in the picture).
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import ValidationError

from ..config import Settings, get_settings
from ..matcher import filter_findings, match_components, summarise
from ..models.cve import CveRecord, SeverityQualitative, SourceName
from ..models.dto import (
    CveLookupRequest,
    CveLookupResponse,
    ErrorResponse,
    IngestRequest,
    IngestResponse,
    MatchRequest,
    MatchResponse,
    ScoreRequest,
    ScoreResponse,
    SourceStats,
    StatsResponse,
    SyncOnceRequest,
)
from ..scoring import aggregate_severity
from ..sources import EpssClient, GhsaSource, KevClient, NvdSource, OsvSource, VulnerabilitySource
from ..store import CveStore
from ..telemetry import (
    configure_logging,
    get_logger,
    vuln_intel_http_request_duration_seconds,
    vuln_intel_http_requests_total,
    vuln_intel_ingest_duration_seconds,
    vuln_intel_ingest_total,
    vuln_intel_match_findings,
    vuln_intel_score_requests_total,
    vuln_intel_source_up,
)

logger = get_logger(__name__)


class Service:
    """The application object — owns the store, sources, and caches."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = CveStore(settings.data_dir, settings.store_filename)
        self.sources: dict[SourceName, VulnerabilitySource] = {
            SourceName.NVD: NvdSource(settings),
            SourceName.GHSA: GhsaSource(settings),
            SourceName.OSV: OsvSource(settings),
        }
        self.epss = EpssClient(settings)
        self.kev = KevClient(settings)
        self._last_ingest_at: dict[SourceName, datetime] = {}
        self._last_ingest_error: dict[SourceName, str] = {}
        self._shutdown = asyncio.Event()

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        await self.store.open()
        # Eager KEV load — it's a single GET and we use it for every match.
        try:
            await self.kev.refresh()
        except httpx.HTTPError as exc:
            logger.warning("startup_kev_refresh_failed", error=str(exc))
        self._refresh_source_gauge()

    async def stop(self) -> None:
        self._shutdown.set()
        for s in self.sources.values():
            close = getattr(s, "aclose", None)
            if close is not None:
                try:
                    await close()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("source_close_failed", source=getattr(s, "name", "?"), error=str(exc))
        await self.epss.aclose()
        await self.kev.aclose()
        await self.store.close()

    # ---------------------------------------------------------------- ingestion
    async def ingest(self, req: IngestRequest) -> IngestResponse:
        job_id = uuid.uuid4().hex
        started = datetime.utcnow()
        logger.info(
            "ingest_start",
            job_id=job_id,
            sources=[s.value for s in req.sources],
            full=req.full,
        )
        results: dict[SourceName, int] = {}
        errors: dict[SourceName, str] = {}
        merged_total = 0
        skipped_total = 0
        for src in req.sources:
            source = self.sources.get(src)
            if source is None:
                errors[src] = "unknown source"
                continue
            t0 = time.perf_counter()
            try:
                emitted = 0
                async for rec in source.fetch(
                    since=None if req.full else None,
                    limit=req.max_per_source,
                    full=req.full,
                ):
                    is_new = await self.store.upsert(rec)
                    if is_new:
                        vuln_intel_ingest_total.labels(source=src.value, result="new").inc()
                        merged_total += 1
                    else:
                        vuln_intel_ingest_total.labels(source=src.value, result="merged").inc()
                        merged_total += 1
                    emitted += 1
                    if req.max_per_source and emitted >= req.max_per_source:
                        break
                elapsed = time.perf_counter() - t0
                vuln_intel_ingest_duration_seconds.labels(source=src.value).observe(elapsed)
                results[src] = emitted
                self._last_ingest_at[src] = datetime.utcnow()
                self._last_ingest_error.pop(src, None)
            except (httpx.HTTPError, ValueError) as exc:
                errors[src] = str(exc)
                self._last_ingest_error[src] = str(exc)
                logger.error("ingest_source_failed", source=src.value, error=str(exc))

        # Enrich with EPSS + KEV in the background
        asyncio.create_task(self._enrich_all())

        self._refresh_source_gauge()
        finished = datetime.utcnow()
        duration = (finished - started).total_seconds()
        logger.info("ingest_done", job_id=job_id, duration_s=duration, fetched=results)
        return IngestResponse(
            job_id=job_id,
            started_at=started,
            finished_at=finished,
            duration_s=duration,
            requested_sources=req.sources,
            fetched=results,
            merged=merged_total,
            skipped=skipped_total,
            errors=errors,
        )

    async def _enrich_all(self) -> None:
        try:
            cve_ids = [r.id for r in self.store.all()]
            if not cve_ids:
                return
            scores = await self.epss.fetch(cve_ids[:10_000])
            kev_map = await self.kev.refresh() if not self.kev._cache else self.kev._cache
            updated = 0
            for cid, score in scores.items():
                rec = self.store.get(cid)
                if rec is None:
                    continue
                rec.epss = score
                rec.kev = kev_map.get(cid)
                await self.store.upsert(rec)
                updated += 1
            logger.info("enrich_done", updated=updated)
        except Exception as exc:  # noqa: BLE001
            logger.warning("enrich_failed", error=str(exc))

    # ---------------------------------------------------------------- lookup
    async def lookup(self, req: CveLookupRequest) -> CveLookupResponse:
        found: list[CveRecord] = []
        missing: list[str] = []
        for cid in req.ids:
            rec = self.store.get(cid)
            if rec is None:
                # Fallback to upstream
                for source in self.sources.values():
                    try:
                        rec = await source.fetch_one(cid)
                    except httpx.HTTPError as exc:
                        logger.warning("upstream_lookup_failed", source=source.name, id=cid, error=str(exc))
                        continue
                    if rec is not None:
                        await self.store.upsert(rec)
                        break
            if rec is not None:
                if not req.include_raw:
                    rec = rec.model_copy(update={"raw": {}})
                found.append(rec)
            else:
                missing.append(cid)
        return CveLookupResponse(found=found, missing=missing, total=len(found))

    async def get(self, cve_id: str) -> CveRecord:
        rec = self.store.get(cve_id)
        if rec is not None:
            return rec
        for source in self.sources.values():
            try:
                rec = await source.fetch_one(cve_id)
            except httpx.HTTPError as exc:
                logger.warning("upstream_get_failed", source=source.name, id=cve_id, error=str(exc))
                continue
            if rec is not None:
                await self.store.upsert(rec)
                return rec
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE not found: {cve_id}",
        )

    # ---------------------------------------------------------------- scoring
    async def score(self, req: ScoreRequest) -> ScoreResponse:
        vuln_intel_score_requests_total.labels(kind="bulk" if req.cve_ids else "all").inc()
        ids = req.cve_ids or [r.id for r in self.store.all()]
        scored: list[CveRecord] = []
        errors: list[str] = []
        unchanged = 0
        # EPSS
        if req.refresh_epss and ids:
            try:
                epss_map = await self.epss.fetch(ids[:10_000])
            except httpx.HTTPError as exc:
                logger.warning("epss_fetch_failed", error=str(exc))
                epss_map = {}
        else:
            epss_map = {}
        # KEV
        if req.refresh_kev:
            try:
                await self.kev.refresh()
            except httpx.HTTPError as exc:
                logger.warning("kev_refresh_failed", error=str(exc))
        for cid in ids:
            rec = self.store.get(cid)
            if rec is None:
                errors.append(f"not found: {cid}")
                continue
            new_epss = epss_map.get(cid.upper())
            new_kev = self.kev._cache.get(cid.upper())
            if new_epss and rec.epss and new_epss.fetched_at <= rec.epss.fetched_at:
                unchanged += 1
            if new_epss:
                rec.epss = new_epss
            if new_kev:
                rec.kev = new_kev
            if not rec.severity:
                rec.severity = aggregate_severity()
            await self.store.upsert(rec)
            scored.append(rec)
        return ScoreResponse(scored=scored, unchanged=unchanged, errors=errors)

    # ---------------------------------------------------------------- matching
    async def match(self, req: MatchRequest) -> MatchResponse:
        records = self.store.all()
        findings = match_components(
            req.components,
            records,
            min_severity=req.min_severity,
            exploited_only=req.include_exploited_only,
        )
        # Already filtered inside match_components
        for f in findings:
            vuln_intel_match_findings.labels(severity=f.cve.severity.qualitative.value).inc()
        sev_counts = summarise(findings)
        affected_components = len({f.component.name.lower() for f in findings})
        return MatchResponse(
            findings=findings,
            total_components=len(req.components),
            affected_components=affected_components,
            severity_counts=sev_counts,
        )

    # ---------------------------------------------------------------- stats
    async def stats(self) -> StatsResponse:
        per_source: list[SourceStats] = []
        records = self.store.all()
        for src in SourceName:
            count = sum(1 for r in records if src in r.source)
            per_source.append(
                SourceStats(
                    source=src,
                    records=count,
                    last_ingest_at=self._last_ingest_at.get(src),
                    last_error=self._last_ingest_error.get(src),
                )
            )
        kev_count = sum(1 for r in records if r.kev and r.kev.exploited)
        epss_scored = sum(1 for r in records if r.epss is not None)
        sev = summarise_records(records)
        cache_hit = sum(s.hit_ratio for s in self.sources.values()) / max(1, len(self.sources))
        return StatsResponse(
            total_records=len(records),
            by_source=per_source,
            cache_hit_ratio=cache_hit,
            kev_count=kev_count,
            epss_scored=epss_scored,
            severity_distribution=sev,
        )

    def _refresh_source_gauge(self) -> None:
        for src in SourceName:
            vuln_intel_source_up.labels(source=src.value).set(1 if src in self.sources else 0)
        for src, recs in _group_by_source(self.store.all()).items():
            vuln_intel_records_stored.labels(source=src.value).set(len(recs))


def summarise_records(records: list[CveRecord]) -> dict[SeverityQualitative, int]:
    from collections import Counter

    c: Counter[SeverityQualitative] = Counter()
    for r in records:
        c[r.severity.qualitative] += 1
    return dict(c)


def _group_by_source(records: list[CveRecord]) -> dict[SourceName, list[CveRecord]]:
    out: dict[SourceName, list[CveRecord]] = {s: [] for s in SourceName}
    for r in records:
        for s in r.source:
            out.setdefault(s, []).append(r)
    return out


# ----------------------------------------------------------------------------
# FastAPI plumbing
# ----------------------------------------------------------------------------


def _auth_dependency(settings: Settings):
    def _dep(request: Request) -> dict[str, Any] | None:
        if not settings.auth_required:
            return {"sub": "anonymous", "tenant": settings.tenant_id}
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = auth.split(" ", 1)[1]
        if not settings.auth_jwt_secret:
            raise HTTPException(status_code=503, detail="auth not configured")
        try:
            claims = jwt.decode(
                token,
                settings.auth_jwt_secret,
                algorithms=[settings.auth_jwt_algorithm],
                audience=settings.auth_jwt_audience,
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}") from exc
        return claims

    return _dep


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    service = Service(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await service.start()
        app.state.service = service
        try:
            yield
        finally:
            await service.stop()

    app = FastAPI(
        title="vuln-intel",
        version="0.1.0",
        lifespan=lifespan,
        description="CVE ingestion, normalization, and scoring (NVD + GHSA + OSV + EPSS + KEV).",
    )

    # ---------------------------------------------------------------- auth
    auth_dep = _auth_dependency(settings)

    # ---------------------------------------------------------------- middleware
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        t0 = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:
            status_code = 500
            raise
        else:
            status_code = response.status_code
        elapsed = time.perf_counter() - t0
        path = request.url.path
        vuln_intel_http_requests_total.labels(
            method=request.method, path=path, status=str(status_code)
        ).inc()
        vuln_intel_http_request_duration_seconds.labels(method=request.method, path=path).observe(elapsed)
        return response

    # ---------------------------------------------------------------- routes — health
    @app.get("/livez", include_in_schema=False)
    async def livez() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> dict[str, Any]:
        results: dict[str, bool] = {}
        for src, src_obj in service.sources.items():
            try:
                results[src.value] = await src_obj.health()
            except Exception:  # noqa: BLE001
                results[src.value] = False
        results["kev"] = await service.kev.health()
        results["epss"] = await service.epss.health()
        all_ok = all(results.values())
        return {"ready": all_ok, "sources": results}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ---------------------------------------------------------------- routes — API
    @app.post("/vuln-intel/ingest", response_model=IngestResponse)
    async def ingest(
        req: IngestRequest, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> IngestResponse:
        _ = claims
        return await service.ingest(req)

    @app.get("/vuln-intel/cve/{cve_id}", response_model=CveRecord)
    async def get_cve(
        cve_id: str, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> CveRecord:
        _ = claims
        try:
            return await service.get(cve_id)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/vuln-intel/cve/lookup", response_model=CveLookupResponse)
    async def lookup_cve(
        req: CveLookupRequest, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> CveLookupResponse:
        _ = claims
        return await service.lookup(req)

    @app.post("/vuln-intel/score", response_model=ScoreResponse)
    async def score(
        req: ScoreRequest, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> ScoreResponse:
        _ = claims
        return await service.score(req)

    @app.post("/vuln-intel/match", response_model=MatchResponse)
    async def match(
        req: MatchRequest, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> MatchResponse:
        _ = claims
        return await service.match(req)

    @app.post("/vuln-intel/sync/once", response_model=IngestResponse)
    async def sync_once(
        req: SyncOnceRequest | None = None,
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> IngestResponse:
        _ = claims
        req_obj = req or SyncOnceRequest()
        sources = req_obj.sources or [SourceName.NVD, SourceName.GHSA, SourceName.OSV]
        return await service.ingest(IngestRequest(sources=sources, full=req_obj.full))

    @app.get("/vuln-intel/stats", response_model=StatsResponse)
    async def stats(
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> StatsResponse:
        _ = claims
        return await service.stats()

    # ---------------------------------------------------------------- errors
    @app.exception_handler(ValidationError)
    async def _validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="validation",
                message="request payload failed validation",
                details={"errors": exc.errors()},
            ).model_dump(),
        )

    @app.exception_handler(HTTPException)
    async def _http_handler(_: Request, exc: HTTPException) -> JSONResponse:
        kind = {401: "auth", 404: "not_found"}.get(exc.status_code, "internal")
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(error=kind, message=str(exc.detail)).model_dump(),
        )

    return app


app = create_app()
