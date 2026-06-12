---
name: S2.7 Shared Metrics Helper + Spec Compliance (FullstackEngineer)
description: Created `backend/common/observability/metrics.ts` helper per SRE spec; refactored security-service :4003 metrics to use it; dropped `tenant_id_hash` (forbidden per metrics-spec.md §5.1); added `@aicc/observability` path mapping.
type: project
---

# S2.7 — Shared Metrics Helper + Spec Compliance

## Context
- SREEngineer (2026-06-12) requested `backend/common/observability/metrics.ts` helper
- Reason: `prom-client` does NOT auto-add the `service` label like Python OTel SDK does
- Re-read `docs/observability/metrics-spec.md` §5.1: `tenant_id` is **forbidden** on metrics (high-cardinality, PII)
- Sprint 2 work by FullstackEngineer

## Spec compliance finding
- §5.1 forbids these labels on metrics: `tenant_id`, `user_id`, `request_id`, `agent_id`, `worker_id`, `trace_id`
- My earlier `tenant_id_hash` falls in the same trap (one series per tenant + hash doesn't fix correlation)
- **Dropped `tenant_id_hash` from all 6 security-service metrics**

## Helper module (NEW)
File: `backend/common/observability/metrics.ts` (~180 lines)
Exports:
- `serviceName: string` (from `OTEL_SERVICE_NAME` env, fallback 'unknown')
- `defaultRegistry: Registry` (per-service, isolated)
- `createCounter(opts)` — auto-injects `service` label
- `createHistogram(opts)` — auto-injects `service` label
- `withService(labels)` — prepends `service` at call site
- `renderMetrics(registry?)` — body + contentType for `/metrics` endpoint
- `assertNoForbiddenLabels(labelNames, context)` — fail-fast at metric construction
- `FORBIDDEN_METRIC_LABELS: readonly string[]` — list per §5.1
- `DEFAULT_LATENCY_BUCKETS: number[]` — `[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30]`

Barrel: `backend/common/observability/index.ts` — re-exports from otel/logger/health/metrics
Path mapping added to `backend/tsconfig.base.json`:
```json
"@aicc/observability": ["common/observability/index.ts"],
"@aicc/observability/*": ["common/observability/*"]
```

## Security-service refactor
6 metric instances now created via `createCounter`/`createHistogram` from `@aicc/observability`. All 6 auto-inject `service` via `withService({...})` at every `inc()`/`observe()` call.

Files modified:
- `services/security/src/services/metrics.ts` — full rewrite using helper; dropped `hashTenantId`/`configureMetricsSalt`
- `services/security/src/services/proxy.ts` — dropped `tenant_id_hash` from labels
- `services/security/src/middleware/auth.ts` — dropped `tenant_id_hash` from labels
- `services/security/src/middleware/rbac.ts` — dropped `tenant_id_hash` from labels
- `services/security/src/routes/dashboard.ts` — dropped `tenant_id_hash` from labels
- `services/security/src/index.ts` — dropped `configureMetricsSalt`; uses helper's `renderMetrics`
- `services/security/src/config.ts` — dropped `METRICS_TENANT_SALT`; added `OTEL_SERVICE_NAME`
- `services/security/.env.example` — updated env vars section
- `services/security/README.md` — Observability section rewritten

## Updated cardinality (well under 50k budget)
- proxy_request_duration_seconds: 5 routes × 3 targets × 2 results × 14 buckets = ~420 series
- proxy_request_total: 5 × 3 × ~6 status = ~90
- eventbus_publish_total: 3 topics × 2 results = 6
- rate_limit_triggered_total: 5 routes = 5
- auth_failure_total: 5 routes × 5 reasons = 25
- dashboard_query_duration_seconds: 1 endpoint × 14 buckets = ~14
- Total: ~560 series (no `service` multiplier — 1 series per metric per service)

## Sprint 3 path
- Helper is in place; 4 other Node services (auth, agent, incident, compliance, integration) can adopt with 3-line change each
- Optional: full OTel migration (`@opentelemetry/exporter-prometheus`) deferred to Sprint 3 (per SRE)
