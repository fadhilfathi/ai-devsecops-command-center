"""FastAPI app factory for dependency-intel."""
from __future__ import annotations

import asyncio
import io
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from ..config import Settings, get_settings
from ..builder import build_graph
from ..correlator import VulnIntelClient, build_match_payload, ingest_correlation
from ..models.dto import (
    ClustersResponse,
    CorrelateRequest,
    CorrelateResponse,
    ErrorResponse,
    GraphExportFormat,
    GraphSummary,
    RiskCalculateRequest,
    RiskCalculateResponse,
    SbomIngestRequest,
    SbomIngestResponse,
)
from ..models.graph import DependencyGraph, RiskComputation, VulnerabilityCluster
from ..risk import compute_risk, find_vulnerability_clusters
from ..store import GraphStore
from ..telemetry import (
    configure_logging,
    REGISTRY,
    dep_intel_correlation_total,
    dep_intel_graph_edges,
    dep_intel_graph_nodes,
    dep_intel_graphs_stored,
    dep_intel_http_request_duration_seconds,
    dep_intel_http_requests_total,
    dep_intel_risk_compute_duration_seconds,
    dep_intel_vuln_intel_up,
    get_logger,
)
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

logger = get_logger(__name__)


class Service:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = GraphStore(settings.data_dir, settings.graph_filename)
        self.vuln_intel = VulnIntelClient(settings)

    # ---------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        await self.store.open()
        try:
            ok = await self.vuln_intel.health()
            dep_intel_vuln_intel_up.set(1 if ok else 0)
        except httpx.HTTPError as exc:
            logger.warning("vuln_intel_unreachable: %s", exc)
            dep_intel_vuln_intel_up.set(0)
        self._refresh_gauges()

    async def stop(self) -> None:
        await self.vuln_intel.aclose()
        await self.store.close()

    def _refresh_gauges(self) -> None:
        dep_intel_graphs_stored.set(len(self.store))
        for g in self.store.all():
            dep_intel_graph_nodes.set(g.node_count)
            dep_intel_graph_edges.set(g.edge_count)
            break  # only emit the "latest"

    # ---------------------------------------------------------------- ingest
    async def ingest_sbom(self, req: SbomIngestRequest) -> SbomIngestResponse:
        t0 = time.perf_counter()
        existing = None
        if req.workspace:
            existing = self.store.get_by_sbom(req.sbom_id)
        graph, added_nodes, added_edges, skipped = build_graph(
            req, existing=existing, max_nodes=self.settings.max_graph_nodes, max_edges=self.settings.max_graph_edges
        )
        if not graph.id:
            graph.id = "g_" + uuid.uuid4().hex[:12]
        await self.store.save(graph)
        self._refresh_gauges()
        took = time.perf_counter() - t0
        return SbomIngestResponse(
            graph_id=graph.id,
            sbom_id=req.sbom_id,
            added_nodes=added_nodes,
            added_edges=added_edges,
            skipped_nodes=skipped,
            total_nodes=graph.node_count,
            total_edges=graph.edge_count,
            took_s=took,
        )

    # ---------------------------------------------------------------- fetch
    def get_graph(self, graph_id: str) -> DependencyGraph:
        g = self.store.get(graph_id)
        if g is None:
            raise HTTPException(status_code=404, detail=f"graph not found: {graph_id}")
        return g

    def summary(self, graph_id: str) -> GraphSummary:
        g = self.get_graph(graph_id)
        return GraphSummary(
            id=g.id,
            name=g.name,
            sbom_ids=g.sbom_ids,
            node_count=g.node_count,
            edge_count=g.edge_count,
            created_at=g.created_at,
            updated_at=g.updated_at,
        )

    # ---------------------------------------------------------------- correlate
    async def correlate(self, graph_id: str, req: CorrelateRequest) -> CorrelateResponse:
        t0 = time.perf_counter()
        g = self.get_graph(graph_id)
        if not req.refresh_from_vuln_intel:
            # Just re-attach from existing findings — no-op for now
            return CorrelateResponse(
                graph_id=graph_id,
                nodes_with_findings=sum(1 for n in g.nodes.values() if n.findings),
                findings_attached=sum(len(n.findings) for n in g.nodes.values()),
                severity_distribution={},
                took_s=time.perf_counter() - t0,
            )
        payload = build_match_payload(g)
        # Send in chunks of 1000 to avoid huge request bodies
        all_findings: list[dict[str, Any]] = []
        chunk = 1_000
        for i in range(0, len(payload), chunk):
            batch = await self.vuln_intel.match_components(
                payload[i : i + chunk],
                min_severity=req.min_severity,
                exploited_only=req.exploited_only,
            )
            all_findings.extend(batch)
        attached, sev_dist = ingest_correlation(g, all_findings)
        # Persist
        await self.store.save(g)
        for sev, n in sev_dist.items():
            dep_intel_correlation_total.labels(severity=sev).inc(n)
        took = time.perf_counter() - t0
        return CorrelateResponse(
            graph_id=graph_id,
            nodes_with_findings=sum(1 for n in g.nodes.values() if n.findings),
            findings_attached=attached,
            severity_distribution=sev_dist,
            took_s=took,
        )

    # ---------------------------------------------------------------- risk
    async def risk(self, graph_id: str, req: RiskCalculateRequest) -> RiskCalculateResponse:
        g = self.get_graph(graph_id)
        alpha = req.alpha if req.alpha is not None else self.settings.risk_alpha
        damping = req.damping if req.damping is not None else self.settings.risk_damping
        t0 = time.perf_counter()
        scores, computation = compute_risk(
            g, alpha=alpha, damping=damping, max_iter=req.max_iter, tol=req.tol
        )
        dep_intel_risk_compute_duration_seconds.observe(time.perf_counter() - t0)
        await self.store.save(g)
        return RiskCalculateResponse(graph_id=graph_id, result=computation, risk_scores=scores)

    # ---------------------------------------------------------------- clusters
    def clusters(self, graph_id: str) -> ClustersResponse:
        g = self.get_graph(graph_id)
        clusters = find_vulnerability_clusters(g)
        return ClustersResponse(graph_id=graph_id, clusters=clusters, total_clusters=len(clusters))

    # ---------------------------------------------------------------- export
    def export(self, graph_id: str, fmt: GraphExportFormat) -> Response:
        g = self.get_graph(graph_id)
        if fmt == GraphExportFormat.JSON:
            return Response(
                content=g.model_dump_json(by_alias=True, indent=2),
                media_type="application/json",
            )
        if fmt == GraphExportFormat.GRAPHML:
            return Response(
                content=_to_graphml(g),
                media_type="application/xml",
            )
        if fmt == GraphExportFormat.DOT:
            return Response(content=_to_dot(g), media_type="text/vnd.graphviz")
        raise HTTPException(status_code=400, detail=f"unsupported format: {fmt}")


# ============================================================================
# Exporters
# ============================================================================


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _to_graphml(g: DependencyGraph) -> str:
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<graphml>", "  <graph id=\"" + _xml_escape(g.id) + "\" edgedefault=\"directed\">"]
    for nid, node in g.nodes.items():
        parts.append(
            f'    <node id="{_xml_escape(nid)}">'
            f'<data key="name">{_xml_escape(node.name)}</data>'
            f'<data key="ecosystem">{_xml_escape(node.ecosystem or "")}</data>'
            f'<data key="version">{_xml_escape(node.version or "")}</data>'
            f'<data key="risk">{node.risk_score:.2f}</data>'
            f'<data key="is_direct">{str(node.is_direct).lower()}</data>'
            f'</node>'
        )
    for e in g.edges:
        parts.append(
            f'    <edge source="{_xml_escape(e.from_node)}" target="{_xml_escape(e.to_node)}">'
            f'<data key="kind">{_xml_escape(e.kind)}</data>'
            f'</edge>'
        )
    parts.append("  </graph>")
    parts.append("</graphml>")
    return "\n".join(parts)


def _to_dot(g: DependencyGraph) -> str:
    parts = [f"digraph \"{g.id}\" {{", "  rankdir=LR;", '  node [shape=box, style="rounded,filled", fillcolor="#ffffff"];']
    for nid, node in g.nodes.items():
        color = _risk_color(node.risk_score)
        parts.append(f'  "{_xml_escape(nid)}" [label="{_xml_escape(node.name)}\\n{_xml_escape(node.version or "")}", fillcolor="{color}"];')
    for e in g.edges:
        parts.append(f'  "{_xml_escape(e.from_node)}" -> "{_xml_escape(e.to_node)}" [label="{_xml_escape(e.kind)}"];')
    parts.append("}")
    return "\n".join(parts)


def _risk_color(score: float) -> str:
    if score >= 75:
        return "#fee2e2"  # red-100
    if score >= 50:
        return "#ffedd5"  # orange-100
    if score >= 25:
        return "#fef9c3"  # yellow-100
    if score >= 10:
        return "#dcfce7"  # green-100
    return "#ffffff"


# ============================================================================
# FastAPI app
# ============================================================================


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
        title="dependency-intel",
        version="0.1.0",
        lifespan=lifespan,
        description="Dependency graph + risk propagation + vulnerability correlation.",
    )
    auth_dep = _auth_dependency(settings)

    @app.middleware("http")
    async def metrics_mw(request: Request, call_next):
        t0 = time.perf_counter()
        try:
            response: Response = await call_next(request)
            status_code = response.status_code
        except Exception:
            status_code = 500
            raise
        elapsed = time.perf_counter() - t0
        path = request.url.path
        dep_intel_http_requests_total.labels(method=request.method, path=path, status=str(status_code)).inc()
        dep_intel_http_request_duration_seconds.labels(method=request.method, path=path).observe(elapsed)
        return response

    @app.get("/livez", include_in_schema=False)
    async def livez() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> dict[str, Any]:
        ok_vi = await service.vuln_intel.health()
        return {
            "ready": True,
            "vuln_intel": ok_vi,
            "graphs_stored": len(service.store),
        }

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    @app.post("/dep-intel/graph/build", response_model=SbomIngestResponse)
    async def build(
        req: SbomIngestRequest, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> SbomIngestResponse:
        _ = claims
        return await service.ingest_sbom(req)

    @app.get("/dep-intel/graph/{graph_id}", response_model=GraphSummary)
    async def get_summary(
        graph_id: str, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> GraphSummary:
        _ = claims
        return service.summary(graph_id)

    @app.get("/dep-intel/graph/{graph_id}/full", response_model=DependencyGraph)
    async def get_full(
        graph_id: str, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> DependencyGraph:
        _ = claims
        return service.get_graph(graph_id)

    @app.post("/dep-intel/graph/{graph_id}/correlate", response_model=CorrelateResponse)
    async def correlate(
        graph_id: str,
        req: CorrelateRequest | None = None,
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> CorrelateResponse:
        _ = claims
        return await service.correlate(graph_id, req or CorrelateRequest())

    @app.post("/dep-intel/risk/calculate", response_model=RiskCalculateResponse)
    async def risk(
        graph_id: str = Query(...),
        req: RiskCalculateRequest | None = None,
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> RiskCalculateResponse:
        _ = claims
        return await service.risk(graph_id, req or RiskCalculateRequest())

    @app.get("/dep-intel/risk/{graph_id}", response_model=RiskCalculateResponse)
    async def risk_for(
        graph_id: str,
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> RiskCalculateResponse:
        _ = claims
        return await service.risk(graph_id, RiskCalculateRequest())

    @app.get("/dep-intel/clusters/{graph_id}", response_model=ClustersResponse)
    async def clusters(
        graph_id: str, claims: dict[str, Any] | None = Depends(auth_dep)
    ) -> ClustersResponse:
        _ = claims
        return service.clusters(graph_id)

    @app.get("/dep-intel/graph/{graph_id}/export")
    async def export(
        graph_id: str,
        fmt: GraphExportFormat = Query(GraphExportFormat.JSON),
        claims: dict[str, Any] | None = Depends(auth_dep),
    ) -> Response:
        _ = claims
        return service.export(graph_id, fmt)

    @app.exception_handler(HTTPException)
    async def _http_handler(_: Request, exc: HTTPException) -> JSONResponse:
        kind = {401: "auth", 404: "not_found"}.get(exc.status_code, "internal")
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(error=kind, message=str(exc.detail)).model_dump(),
        )

    return app


app = create_app()
