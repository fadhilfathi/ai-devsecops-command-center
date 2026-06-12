# =============================================================================
# Health check server — Python reference (Sprint 2)
# Owner: SREEngineer
# See: docs/observability/monitoring-architecture.md §6
#
# Mirror of backend/common/observability/health.ts.
# Uses FastAPI on a separate management port (default 9090).
#   - /healthz (liveness)  — shallow; never checks dependencies
#   - /readyz  (readiness) — deep; checks DB, CVE feed, bus connection
#   - /startz  (startup)   — returns 503 until first /readyz success
# =============================================================================

from __future__ import annotations

import asyncio
import datetime as _dt
import os
from typing import Awaitable, Callable

from fastapi import FastAPI, Response, status

CheckFn = Callable[[], Awaitable[dict]]


class HealthCheck:
    """
    A named, optionally-required health check with a per-check timeout.

    The `run` coroutine must return a dict like:
        {"ok": True, "latency_ms": 4, "detail": "..."}    # detail optional
    or raise an exception on failure.
    """

    def __init__(
        self,
        name: str,
        run: CheckFn,
        required: bool = True,
        timeout_ms: int = 250,
    ):
        self.name = name
        self.run = run
        self.required = required
        self.timeout_ms = timeout_ms


def build_health_app(
    service: str,
    version: str,
    started_at: _dt.datetime,
    checks: list[HealthCheck],
    default_timeout_ms: int = 250,
) -> FastAPI:
    """
    Build a FastAPI app exposing the three health probes. Mount on a separate
    port via uvicorn in each service's entrypoint.
    """
    app = FastAPI(
        title=f"{service} health",
        docs_url=None,  # never expose swagger on the management port
        redoc_url=None,
    )
    state = {"startup_complete": False}

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "service": service, "version": version}

    @app.get("/startz")
    async def startz(response: Response) -> dict:
        if not state["startup_complete"]:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "starting"}
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(response: Response) -> dict:
        results: dict[str, dict] = {}
        all_ok = True
        any_required_failed = False

        async def _run_one(check: HealthCheck) -> tuple[str, dict]:
            timeout_s = (check.timeout_ms or default_timeout_ms) / 1000.0
            started = _dt.datetime.now(_dt.timezone.utc)
            try:
                result = await asyncio.wait_for(check.run(), timeout=timeout_s)
                ok = bool(result.get("ok"))
                entry = {
                    "status": "ok" if ok else "fail",
                    "latency_ms": result.get(
                        "latency_ms",
                        int((_dt.datetime.now(_dt.timezone.utc) - started).total_seconds() * 1000),
                    ),
                }
                if "detail" in result:
                    entry["detail"] = result["detail"]
                return check.name, entry, ok
            except asyncio.TimeoutError:
                return check.name, {
                    "status": "fail",
                    "latency_ms": check.timeout_ms,
                    "detail": f"timeout after {check.timeout_ms}ms",
                }, False
            except Exception as exc:
                return check.name, {
                    "status": "fail",
                    "latency_ms": int(
                        (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds() * 1000
                    ),
                    "detail": str(exc),
                }, False

        outcomes = await asyncio.gather(
            *(_run_one(c) for c in checks), return_exceptions=False
        )
        for name, entry, ok in outcomes:
            results[name] = entry
            if not ok:
                all_ok = False
                if any(c.name == name and c.required for c in checks):
                    any_required_failed = True

        if all_ok:
            state["startup_complete"] = True

        response.status_code = (
            status.HTTP_503_SERVICE_UNAVAILABLE if any_required_failed else status.HTTP_200_OK
        )
        return {
            "status": "fail" if any_required_failed else "ok",
            "checks": results,
            "version": version,
            "uptime_s": int(
                (_dt.datetime.now(_dt.timezone.utc) - started_at).total_seconds()
            ),
        }

    return app


# ---------------------------------------------------------------------------
# Example check builders
# ---------------------------------------------------------------------------
async def sqlite_writable_check(conn_factory, required: bool = True) -> HealthCheck:
    """
    Build a /readyz check for SQLite. Pass a callable that returns a new
    sqlite3 connection each call.
    """
    async def _run() -> dict:
        started = _dt.datetime.now(_dt.timezone.utc)
        loop = asyncio.get_running_loop()
        # SQLite is sync; run in a thread to keep the event loop free.
        def _probe() -> None:
            conn = conn_factory()
            try:
                cur = conn.execute("SELECT 1")
                cur.fetchone()
            finally:
                conn.close()
        await loop.run_in_executor(None, _probe)
        return {
            "ok": True,
            "latency_ms": int(
                (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds() * 1000
            ),
        }

    return HealthCheck(name="sqlite", run=_run, required=required)


async def http_url_reachable_check(
    name: str,
    url: str,
    required: bool = True,
    timeout_ms: int = 2000,
) -> HealthCheck:
    """
    Build a /readyz check for a remote URL (CVE feed, dependency track, etc.).
    """
    import httpx

    async def _run() -> dict:
        started = _dt.datetime.now(_dt.timezone.utc)
        async with httpx.AsyncClient(timeout=timeout_ms / 1000) as client:
            r = await client.get(url)
            return {
                "ok": r.status_code < 500,
                "latency_ms": int(
                    (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds() * 1000
                ),
                "detail": f"status={r.status_code}",
            }

    return HealthCheck(name=name, run=_run, required=required, timeout_ms=timeout_ms)


async def nats_connected_check(nc, required: bool = True) -> HealthCheck:
    """
    Build a /readyz check for an active NATS connection.
    """
    async def _run() -> dict:
        started = _dt.datetime.now(_dt.timezone.utc)
        if nc.is_closed:
            return {"ok": False, "latency_ms": 0, "detail": "closed"}
        await nc.request("health.ping", b"", timeout=0.2)
        return {
            "ok": True,
            "latency_ms": int(
                (_dt.datetime.now(_dt.timezone.utc) - started).total_seconds() * 1000
            ),
        }

    return HealthCheck(name="nats", run=_run, required=required, timeout_ms=300)


async def config_loaded_check(env_var: str = "CONFIG_LOADED", required: bool = True) -> HealthCheck:
    async def _run() -> dict:
        ok = os.getenv(env_var, "false").lower() in ("true", "1", "yes")
        return {"ok": ok, "latency_ms": 0}
    return HealthCheck(name="config_loaded", run=_run, required=required, timeout_ms=10)
