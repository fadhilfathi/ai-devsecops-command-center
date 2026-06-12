---
name: S2.7 Runtime Observability for Security Stack
description: SREEngineer delivered Python OTel reference, per-service observability hooks, 4 new alert rules, security-stack Grafana dashboard, runbook updates, and docker-compose additions for the 3 Sprint 2 Python services.
type: project
---

# S2.7 — Runtime Observability for Security Stack

## What was delivered
- `backend/common/observability-py/` — Python reference toolkit:
  - `otel.py` — OTel SDK bootstrap (OTLP gRPC, FastAPI/httpx/requests/urllib3/sqlite3 auto-instrumentation, W3C trace context, lifecycle hooks)
  - `logger.py` — structlog with PII redaction, W3C trace context injection, JSON schema validation, **component-name masking in production** (Sprint 2 requirement)
  - `health.py` — FastAPI health server (`/healthz` shallow, `/readyz` deep with per-check timeout, `/startz` slow init), check builders for SQLite, HTTP, NATS, config
  - `metrics.py` — `prometheus_client`-based metrics; standard HTTP + Sprint 2 security-stack metrics; shared `REGISTRY`
  - `__init__.py` + `README.md`
- `backend/services/sbom-pipeline/src/observability.py` — `observe_scan()` context manager; records `devsecops_sbom_generation_duration_seconds`, `devsecops_active_scans`, `devsecops_queue_depth`, `devsecops_eventbus_lag_seconds`
- `backend/services/vuln-intel/src/observability.py` — `record_ingestion_batch()` for `devsecops_vulnerability_ingestion_total`; defensive normalization of unknown sources/severities
- `backend/services/dependency-intel/src/observability.py` — `observe_risk_calc()` context manager; auto-buckets SBOMs into `small|medium|large|xlarge` for `devsecops_risk_calculation_duration_seconds`
- `infra/observability/prometheus/alert-rules.yml` — 4 new alerts appended in a new `security_stack.runtime` group: `SbvomPipelineDown`, `VulnIngestionLag`, `ScanQueueBacklog`, `RiskCalcHighLatency`
- `infra/observability/grafana/dashboards/security-stack.json` — 17 panels across 5 rows (Overview, SBOM, Vuln Ingest, Risk Calc, Queues, Top Risky)
- `docs/observability/alerting-runbooks.md` — 4 new runbooks in §9; version bumped to v1.1
- `infra/docker/docker-compose.yml` — 3 new services on ports 4007/4008/4009; management ports 9407/9408/9409; depends_on nats + otel-collector; service-mesh labels for k8s SD

## Decisions
1. **Python auto-instrumentation excludes the same probe URLs as the TypeScript reference** (`/healthz`, `/readyz`, `/startz`, `/metrics`).
2. **Component-name masking in production** is a Sprint 2 specific requirement (org info can leak via package coordinates). Implemented in `logger._redact_component_name`.
3. **`sbom_size_bucket` label uses 5 fixed values** (`small|medium|large|xlarge|xxlarge`) — locked by PlatformArchitect 2026-06-12. Helper in `metrics.sbom_size_bucket()`. 100/1k/10k/50k thresholds.
4. **Defensive normalization** of unknown feed sources and severities in `vuln-intel` — folds into `unknown` bucket to preserve cardinality ceilings.
5. **Health checks use FastAPI on a separate management port** (`:9090`) to keep probe traffic out of RED metrics. Per-check timeout default 250ms; NATS check gets 300ms; HTTP check gets 2000ms.
6. **OTel Collector is the gateway, not a per-service sidecar** in dev — the docker-compose service name `otel-collector` is shared. The Lead's task said "OTel collector sidecar for each" but the existing `otel-collector` service in the compose is the gateway pattern. Coordinated via environment variable `OTEL_EXPORTER_OTLP_ENDPOINT` per service.
7. **Service-mesh labels** (`ai-devsecops.io/service`, `ai-devsecops.io/readyz`) added so Prometheus k8s SD and Blackbox exporter can discover the services without code changes.

## Decisions (S2.7 follow-up, locked 2026-06-12 by PlatformArchitect)
8. **`devsecops_sbom_generation_duration_seconds` locked labels: `{source_type, ecosystem, target_type, result}`**. Allowed values documented in `metrics.py` and `slos-security-stack.md` §2. `format`, `sbom_size_bucket`, `tenant_id`, `agent_id`, `worker_id` explicitly NOT included.
9. **`devsecops_risk_calculation_duration_seconds` locked labels: `{sbom_size_bucket, algorithm, result}`**. Per-bucket p99 SLOs: small 1s, medium 5s, large 15s, xlarge 60s, xxlarge 300s. New per-bucket alerts added (`RiskCalcHighLatency{Small,Medium,Large,Xlarge,Xxlarge}`).
10. **`devsecops_eventbus_lag_seconds` SLO p99 target: 5 s** (confirmed by SRE). New alert thresholds: 5s=page, 30s=critical, 60s=page on-call lead.
11. **Naming convention** `devsecops_{domain}_{noun}_{unit_suffix}` is now LOCKED. Mandatory unit suffixes per Prometheus convention: `_seconds`, `_total`, `_bytes`, `_ratio`. No camelCase. snake_case only. HELP/TYPE lines required.
12. **Per-service soft cap: 50,000 active time series**. All Sprint 2 metrics fit comfortably.

## Cross-team coordination
- Sent broadcast to SBOMPipelineAgent and VulnerabilityIntelligenceAgent proposing metric names + label sets. Asked for confirmation on extra labels for `devsecops_sbom_generation_duration_seconds` and the `sbom_size_bucket` thresholds for `devsecops_risk_calculation_duration_seconds`. Will assume defaults if no reply.
- PlatformArchitect's platform SLI `platform:event_bus:lag:p99` is fed by `devsecops_eventbus_lag_seconds_bucket` from all 3 services (cross-reference to `docs/architecture/event-bus.md`).

## Open items
- Lead said "OTel collector sidecar for each" but dev compose uses a shared gateway collector. If a per-service sidecar is required, that's a Sprint 3+ change (more memory, more cardinality to manage).
- Dockerfile templates for the 3 services — assumed owned by SBOMPipelineAgent and VulnerabilityIntelligenceAgent. If they need a starter Dockerfile, I can add one in a follow-up PR.
- The `vuln_feed_last_refresh_timestamp_seconds` metric in `VulnIngestionLag` alert is emitted by `vuln-intel` (not in my deliverable; assumed owned by VulnerabilityIntelligenceAgent). Flagged in broadcast.

## Cardinality impact
- `devsecops_sbom_generation_duration_seconds` — 3 services × 4 source_types × 3 results = 36 series. Well under budget.
- `devsecops_vulnerability_ingestion_total` — 3 services × 4 sources × 5 severities = 60 series. Under budget.
- `devsecops_risk_calculation_duration_seconds` — 3 services × 4 buckets = 12 series. Far under.
- `devsecops_active_scans` — 3 services × ~4 scanner types = 12 series. Under.
- `devsecops_queue_depth` — 3 services × ~4 queues = 12 series. Under.
- `devsecops_eventbus_lag_seconds` — 3 services × ~5 streams × ~3 consumer groups × ~10 subjects = ~450 series. Within the 5000 budget for eventbus.

The CI lint (`infra/observability/prometheus/cardinality_lint.py`) will enforce these on every PR.

## Files written
- `backend/common/observability-py/{__init__,otel,logger,health,metrics}.py`
- `backend/common/observability-py/README.md`
- `backend/services/sbom-pipeline/src/observability.py`
- `backend/services/vuln-intel/src/observability.py`
- `backend/services/dependency-intel/src/observability.py`
- `infra/observability/prometheus/alert-rules.yml` (appended)
- `infra/observability/grafana/dashboards/security-stack.json`
- `docs/observability/alerting-runbooks.md` (appended, v1.1)
- `infra/docker/docker-compose.yml` (appended 3 services + 2 volumes)
