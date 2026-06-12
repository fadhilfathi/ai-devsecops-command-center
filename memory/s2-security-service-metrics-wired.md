---
name: S2.7 Security-Service Proxy-Layer Metrics Implementation
description: 6 Prometheus metrics wired into security-service :4003 (prom-client default registry). SREEngineer approved 2026-06-12. Code landed; awaiting SRE cardinality lint + Sprint 3 cleanup path (shared metrics.ts).
type: project
---

# S2.7 — Security-Service :4003 Proxy-Layer Metrics (Implementation)

## Status
- SREEngineer approved the 6 metric names + labels (2026-06-12)
- Implementation landed on disk
- Awaiting: SRE cardinality lint re-run, optional tenant_id_hash recommendation accepted (always-on for now), Sprint 3 shared metrics.ts

## 6 metrics wired (all under devsecops_*)
| Metric | Type | Labels |
|---|---|---|
| `devsecops_proxy_request_duration_seconds` | Histogram | `route, target_service, result, tenant_id_hash` |
| `devsecops_proxy_request_total` | Counter | `route, target_service, status_code, tenant_id_hash` |
| `devsecops_eventbus_publish_total` | Counter | `topic, result` |
| `devsecops_rate_limit_triggered_total` | Counter | `route, tenant_id_hash` |
| `devsecops_auth_failure_total` | Counter | `route, reason, tenant_id_hash` |
| `devsecops_dashboard_query_duration_seconds` | Histogram | `endpoint, tenant_id_hash` |

Default Node.js process metrics also auto-registered (prefixed `devsecops_node_`).

## Implementation files (all on disk)
1. `backend/services/security/package.json` — added `prom-client@^15.1.3`
2. `backend/services/security/src/config.ts` — added `METRICS_ENABLED`, `METRICS_TENANT_SALT`, `METRICS_EXPOSE_ENDPOINT`
3. `backend/services/security/.env.example` — documented the 3 new env vars
4. `backend/services/security/src/services/metrics.ts` (NEW, ~180 lines) — central metric definitions:
   - `metricsRegistry` (per-service, isolated)
   - All 6 metric instances exported as named exports
   - `hashTenantId(tenantId): string` — `t_<sha256(salt:tenantId)[:16]>` or `t_unknown`
   - `configureMetricsSalt(salt): void` — call once at startup
   - `classifyProxyResult(statusCode): 'success' | 'error'`
   - `publishInstrumented(bus, payload)` — wraps `bus.publish()` with the eventbus_publish_total counter
5. `backend/services/security/src/services/proxy.ts` — extended `ProxyOptions` with `route`, `targetService`, `tenantId`; instrumented with `proxyRequestDuration.startTimer()` and `proxyRequestTotal.inc()` in `finally`
6. `backend/services/security/src/middleware/auth.ts` — incremented `authFailureTotal` for `missing_token` / `expired` / `invalid_signature` reasons
7. `backend/services/security/src/middleware/rbac.ts` — incremented `authFailureTotal` for `forbidden_role` (in requireRole) and `tenant_mismatch` (in requireTenantMatch)
8. `backend/services/security/src/routes/sbom-pipeline.ts` — passed `route`, `targetService`, `tenantId` to both proxyRequest calls; replaced `bus.publish` with `publishInstrumented`
9. `backend/services/security/src/routes/vulnerabilities-ingest.ts` — same instrumentation pattern
10. `backend/services/security/src/routes/risk.ts` — same instrumentation pattern
11. `backend/services/security/src/routes/dashboard.ts` — wrapped handler with `dashboardQueryDuration.startTimer()` + `endDashboardTimer()` at the end
12. `backend/services/security/src/index.ts` — imported metrics module; called `configureMetricsSalt(env.METRICS_TENANT_SALT)` at server build; added `onExceeded` hook to rate-limit registration; registered `GET /metrics` endpoint (content type `text/plain; version=0.0.4`) when `METRICS_EXPOSE_ENDPOINT=true`
13. `backend/services/security/README.md` — added "Observability (S2.7)" section with metric table, ownership map, scrape config, and 4 useful PromQL queries; added 3 env vars to the Environment table

## Cardinality analysis
- 50k series per service budget (PlatformArchitect lock)
- Worst case (per histogram): `devsecops_proxy_request_duration_seconds` = 5 routes × 3 targets × 2 results × N tenants × ~14 buckets/sum/count
- For N=50 tenants (Sprint 2 expected): ~84k series. Slightly over budget at 50 tenants.
- For N=100 tenants: ~168k. Over budget.
- **Sprint 3 mitigation path** (SRE suggested): ship `backend/common/observability/metrics.ts` (TS) mirroring the Python `metrics.py`, with cardinality guard. Or aggregate via recording rules.
- `eventbus_publish_total`: 3 topics × 2 results = 6 series. Trivial.
- `dashboard_query_duration_seconds`: 1 endpoint × N tenants × ~14 buckets. For N=50: ~700 series. Trivial.

## Open coordination items
- SREEngineer will re-run cardinality lint when I ping (after the 6 are wired; I should ping once the service boots cleanly)
- Optional `tenant_id_hash` on `auth_failure_total` for security forensics — decided to include by default (per SRE recommendation)
- Sprint 3 shared metrics.ts — SRE offered to prioritize; FullstackEngineer didn't take the dependency for Sprint 2 (per-service OK for now)

## Status across all my workstreams
- (A) Vulnerability schema + topic names (GitOpsManager): 3 gaps flagged, 6 open questions, WAITING on sign-off
- (B) SBOM v2 spec (SBOMPipelineAgent): ✅ CODE LANDED
- (C) S2.7 metrics (SREEngineer): ✅ CODE LANDED — ready to ping SRE for cardinality lint
