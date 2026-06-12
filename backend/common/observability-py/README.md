# Reference Python Observability — `backend/common/observability-py/`

> **Owner:** SREEngineer
> **Sprint:** 2 — Security Stack Runtime Observability
> **Mirror of:** `backend/common/observability/` (TypeScript reference)

This is the SRE-defined target observability toolkit for the three Sprint 2
Python services:

- `sbom-pipeline` (port 4007)
- `vuln-intel` (port 4008)
- `dependency-intel` (port 4009)

## Modules

| Module      | Purpose                                                                          |
|-------------|----------------------------------------------------------------------------------|
| `otel`      | OpenTelemetry SDK bootstrap. OTLP gRPC exporters to the Collector. Auto-instruments FastAPI, httpx, requests, urllib3, sqlite3. Excludes probe endpoints. |
| `logger`    | structlog with W3C trace context propagation, PII redaction, JSON schema validation, and component-name masking in production. |
| `health`    | FastAPI health server with `/healthz` (shallow), `/readyz` (deep, per-check timeout), `/startz` (slow init). Includes check builders for SQLite, HTTP, and NATS. |
| `metrics`   | Prometheus client with the standard `devsecops_<service>_<metric>_<unit>` convention, plus the Sprint 2 security-stack metrics. |

## Quick start

```python
# main.py (FastAPI service entrypoint)
import datetime as _dt
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from observability_py import (
    start_otel, shutdown_otel, create_logger,
    build_health_app,
    render_metrics,
    queue_depth, active_scans, eventbus_lag_seconds,
)

SERVICE = "sbom-pipeline"
VERSION = "1.0.0"
ENV = "dev"

start_otel(service=SERVICE, version=VERSION, env=ENV)
log = create_logger(service=SERVICE, version=VERSION, env=ENV, agent_id="syft-wrapper")

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup.begin", event="service.startup")
    yield
    log.info("shutdown.end", event="service.shutdown")
    shutdown_otel()

app = FastAPI(lifespan=lifespan)

# --- Metrics on a separate management port ---
@app.get("/metrics")
async def metrics():
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)

# --- Health checks on the same management port ---
from observability_py import sqlite_writable_check, nats_connected_check
health = build_health_app(
    service=SERVICE, version=VERSION,
    started_at=_dt.datetime.now(_dt.timezone.utc),
    checks=[
        await sqlite_writable_check(lambda: get_sqlite_conn()),
        await nats_connected_check(nc),
    ],
)
# Mount /healthz, /readyz, /startz into a separate FastAPI app on port 9090
# (the FastAPIInstrumentor will exclude them from tracing).
```

## Sprint 2 security-stack metrics

Label sets and allowed values are **LOCKED** by PlatformArchitect
(`docs/observability/metrics-spec.md`). The Python definitions below are
the source of truth for emission; the CI lint
(`infra/observability/prometheus/cardinality_lint.py`) enforces the budgets.

| Metric                                              | Type      | Labels                                                                                       |
|-----------------------------------------------------|-----------|----------------------------------------------------------------------------------------------|
| `devsecops_sbom_generation_duration_seconds`        | histogram | `service`, `source_type` (syft/dependency_track/import/manual), `ecosystem` (npm/pypi/maven/nuget/go/cargo/rubygems/composer/conan/apk/deb/rpm/generic), `target_type` (image/filesystem/repo/archive/directory), `result` (success/failure/timeout/cancelled) |
| `devsecops_vulnerability_ingestion_total`           | counter   | `service`, `source` (nvd/ghsa/osv), `severity` (critical/high/medium/low/unknown)            |
| `devsecops_risk_calculation_duration_seconds`       | histogram | `service`, `sbom_size_bucket` (small/medium/large/xlarge/xxlarge), `algorithm` (cvss_only/cvss_epss/cvss_epss_kev/full), `result` (success/failure/timeout/cancelled) |
| `devsecops_active_scans`                            | gauge     | `service`, `scanner_type` (syft/grype/trivy/dependency_track)                                |
| `devsecops_queue_depth`                             | gauge     | `service`, `queue_name`                                                                      |
| `devsecops_eventbus_lag_seconds`                    | histogram | `service`, `stream`, `consumer_group`, `subject` (consumed by PlatformArchitect's platform SLI `platform:event_bus:lag:p99`) |

### Locked label cardinality
- `sbom_generation_duration_seconds` — 4 × 14 × 5 × 4 = 1,120 combos × ~12 buckets = ~13,440 series
- `vulnerability_ingestion_total` — 3 × 5 = 15 combos per service
- `risk_calculation_duration_seconds` — 5 × 4 × 4 = 80 combos per service
- `active_scans` — ~4 combos per service
- `queue_depth` — ~4 combos per service
- `eventbus_lag_seconds` — ~3 services × ~5 streams × ~3 groups × ~10 subjects = ~450 series

All comfortably under the 50,000 active-time-series soft cap per service.

### SLO targets
Per-bucket SLO targets live in `docs/observability/slos-security-stack.md`.
The `RiskCalcHighLatency` and similar alerts in
`infra/observability/prometheus/alert-rules.yml` are calibrated against those
targets.

## Cross-language consistency

The TypeScript reference (`backend/common/observability/`) and this Python
package are kept in sync on:

- Naming convention `devsecops_<service>_<metric>_<unit>`.
- Log schema (`infra/observability/logs/log-schema.json`).
- PII redaction patterns.
- W3C trace context propagation.
- Health-check semantics (`/healthz` shallow, `/readyz` deep with timeout, `/startz` slow init).
- Cardinality budgets.

Differences that are intentional and documented:

- Python uses `prometheus_client`; TypeScript uses `prom-client`.
- Python uses `structlog`; TypeScript uses `pino`. The wire format is identical
  (NDJSON, the same field set, the same redaction patterns).
- Python's FastAPI auto-instrumentation excludes `/healthz`, `/readyz`, `/startz`,
  `/metrics` from tracing; the TypeScript reference does the same with
  `ignoreIncomingRequestHook`.
