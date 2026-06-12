# SREEngineer — Memory: Monitoring, Logging, Metrics Architecture

## Summary
Delivered the full observability architecture for the AI-DevSecOps Command Center: metrics (Prometheus + recording rules + SLO burn alerts), structured logging (NDJSON + JSON schema + redaction), distributed tracing (OTel + tail sampling), health checks, SLO/SLI catalog, and a scalability plan.

## Decisions Made (SREEngineer)
1. **OpenTelemetry first** — single SDK across all 6 services; OTel Collector is the gateway, with Prometheus/Loki/Tempo as the backends.
2. **W3C Trace Context only** — no B3, no proprietary headers.
3. **Prometheus two-tier** with federation — regional Prom (15s, 7d) for live alerting; global Prom (60s, 13mo) for SLO reporting and compliance.
4. **SLO-based alerting only** — multi-window, multi-burn-rate alerts (Google SRE Workbook model). Hard threshold alerts are limited to clear "user is impacted" symptoms.
5. **Cardinality is a budget** — enforced by a CI lint (`infra/observability/prometheus/cardinality_lint.py`).
6. **PII redaction at the SDK boundary** — pino-based redactor in `backend/common/observability/logger.ts`, with a Collector-level safety net.
7. **Audit logs in WORM storage** — S3 Object Lock (compliance mode), 7-year retention; owned jointly with ComplianceOfficer.
8. **Health checks** — split into `/livez` (shallow), `/readyz` (deep with per-check timeout), `/startz` (slow init).
9. **Error budget drives deploy freeze** — admission webhook reads `service_error_budget_remaining_ratio`; CI blocks deploys below 0.
10. **No free-form PII in metric labels** — bounded label cardinality; user_id and email are never metric labels.

## Open Questions to Resolve Later
- Mimir vs. Thanos for long-term storage (decision at 10M series).
- Grafana Beyla eBPF for un-instrumented services (spike in Sprint 3).
- Multi-tenant Grafana org model (default: multi-tenant with row-level security; revisit at 50 tenants).
- Blackbox exporter coverage — which synthetic flows (SRE owner, top 20 user flows).

## Dependencies on Other Tasks
- **PlatformArchitect (event-bus):** `event_bus_lag_seconds_bucket` metric must be emitted by the bus for the platform `event_bus:lag:p99` SLI.
- **SecurityArchitect (auth + GitHub):** `jwt_validation_total{result}` and `webhook_deliveries_total{outcome}` must be emitted by those services.
- **FullstackEngineer (backend skeleton):** all 6 services must adopt the reference OTel bootstrap (`backend/common/observability/otel.ts`) and logger (`backend/common/observability/logger.ts`).
- **ComplianceOfficer:** ownership of audit log retention (WORM/7-year) and the CIS/NIST control mappings (see `docs/compliance/`).

## Files Delivered
- `docs/observability/monitoring-architecture.md` — main architecture
- `docs/observability/slo-sli-definitions.md` — SLO catalog
- `docs/observability/alerting-runbooks.md` — alert rules + runbooks
- `infra/observability/prometheus/recording-rules.yml` — pre-computed SLI series
- `infra/observability/prometheus/alert-rules.yml` — alerting rules
- `infra/observability/prometheus/templates/slo-burn.yml.j2` — SLO burn template
- `infra/observability/prometheus/cardinality_lint.py` — CI lint
- `infra/observability/otel-collector/collector-config.yaml` — prod collector
- `infra/observability/alertmanager/alertmanager.yml` — prod routing
- `infra/observability/logs/log-schema.json` — JSON schema for logs
- `infra/observability/grafana/dashboards/service-overview.json` — service dashboard
- `infra/observability/grafana/provisioning/dashboards/dashboards.yml` — provisioning
- `infra/observability/grafana/provisioning/datasources/datasources.yml` — datasources
- `backend/common/observability/otel.ts` — reference OTel bootstrap
- `backend/common/observability/logger.ts` — reference structured logger
- `backend/common/observability/health.ts` — reference health check server
- `infra/observability/alertmanager/alertmanager.yml` — production alertmanager (also used by docker-compose with dev env vars)

## Risks
- **Loki multi-tenant cost** — at 500 GB/day we need to revisit the storage tier. Plan in §10 of `monitoring-architecture.md`.
- **LLM provider latency** is not in our SLO. If providers are slow, the `agent` SLOs will burn. Need a fallback provider and circuit breaker (Sprint 3).
- **Trace context propagation** depends on every service adopting the OTel SDK. Any non-instrumented service breaks trace continuity.
- **Cardinality explosions** are a real risk during agent experimentation. The lint catches static violations; runtime enforcement is best-effort.
