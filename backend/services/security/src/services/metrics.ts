/**
 * Prometheus metrics for security-service :4003 (S2.7 — proxy layer observability).
 *
 * Uses `@aicc/observability` to auto-inject the `service` label from
 * `OTEL_SERVICE_NAME` (per metrics-spec.md §5.1.1). Drops the earlier
 * `tenant_id_hash` label because §5.1 forbids tenant_id / user_id / etc.
 * on metrics (high-cardinality, PII risk).
 *
 * Metric naming: `devsecops_{domain}_{noun}_{unit_suffix}`
 * (PlatformArchitect Decision #11, locked by SRE 2026-06-12).
 *
 * Ownership boundary (locked 2026-06-12):
 *   - security-service :4003 (this file): owns the 6 proxy-layer metrics below
 *   - sbom-pipeline :4007:   devsecops_sbom_generation_duration_seconds,
 *                            devsecops_active_scans{scanner_type="syft"},
 *                            devsecops_queue_depth{queue_name="sbom_jobs"}
 *   - vuln-intel :4008:      devsecops_vulnerability_ingestion_total,
 *                            devsecops_queue_depth{queue_name="cve_processing"},
 *                            devsecops_vuln_feed_last_refresh_timestamp_seconds
 *   - dependency-intel :4009: devsecops_risk_calculation_duration_seconds
 *   - All 3 Python services: devsecops_eventbus_lag_seconds (PlatformArchitect platform SLI)
 *
 * Cardinality: with the `service` label auto-injected, all 6 metrics
 * have the same per-tenant cardinality concern removed (per metrics-spec.md §5.1).
 *   - proxy_request_duration: 5 routes × 3 targets × 2 results × 14 buckets = ~420 series
 *   - proxy_request_total: 5 × 3 × ~6 status = ~90 series
 *   - eventbus_publish_total: 3 topics × 2 results = 6 series
 *   - rate_limit_triggered_total: 5 routes = 5 series
 *   - auth_failure_total: 5 routes × 5 reasons = 25 series
 *   - dashboard_query_duration: 1 endpoint × 14 buckets = ~14 series
 *   - All well under the 50k budget.
 */
import {
  createCounter,
  createHistogram,
  withService,
  renderMetrics,
  serviceName,
  defaultRegistry as _defaultRegistry,
  type CreateCounterOptions,
  type CreateHistogramOptions,
} from '@aicc/observability';
import type { EventBus } from '@aicc/shared';

// Re-export the helper's `serviceName` and the default registry so
// the /metrics endpoint and other consumers in this service can use them.
export { serviceName, renderMetrics };
export const metricsRegistry = _defaultRegistry;

// ---------- 1. Proxy request latency (security-service → Python service hop) ----------
export const proxyRequestDuration = createHistogram({
  name: 'devsecops_proxy_request_duration_seconds',
  help: 'security-service → Python service proxy hop latency, in seconds.',
  labelNames: ['route', 'target_service', 'result'] as const,
});

// ---------- 2. Proxy request count ----------
export const proxyRequestTotal = createCounter({
  name: 'devsecops_proxy_request_total',
  help: 'Total security-service proxy requests to upstream Python services.',
  labelNames: ['route', 'target_service', 'status_code'] as const,
});

// ---------- 3. Event bus publish count ----------
export const eventbusPublishTotal = createCounter({
  name: 'devsecops_eventbus_publish_total',
  help: 'Total event bus publish attempts from security-service (one per topic emission).',
  labelNames: ['topic', 'result'] as const,
});

// ---------- 4. Rate-limit triggers (429 responses) ----------
export const rateLimitTriggeredTotal = createCounter({
  name: 'devsecops_rate_limit_triggered_total',
  help: 'Total 429 responses from per-route rate limiting in security-service.',
  labelNames: ['route'] as const,
});

// ---------- 5. Auth failures ----------
export const authFailureTotal = createCounter({
  name: 'devsecops_auth_failure_total',
  help: 'Total authentication / authorization failures in security-service.',
  labelNames: ['route', 'reason'] as const,
});

// ---------- 6. Dashboard query duration ----------
export const dashboardQueryDuration = createHistogram({
  name: 'devsecops_dashboard_query_duration_seconds',
  help: 'GET /security/dashboard aggregation latency, in seconds.',
  labelNames: ['endpoint'] as const,
});

// ---------- Result-classification helper ----------

/** Map a proxy HTTP status code to a coarse result label for the histogram. */
export function classifyProxyResult(statusCode: number): 'success' | 'error' {
  return statusCode >= 200 && statusCode < 400 ? 'success' : 'error';
}

// ---------- Instrumented event-bus publish helper ----------

/**
 * Wrap an EventBus.publish() call with metric instrumentation.
 * Increments `devsecops_eventbus_publish_total{topic, result}` once per call
 * (with the `service` label auto-injected by `withService`).
 * Re-throws on failure after incrementing the `error` counter.
 *
 * Use this in place of `bus.publish()` at every emission site in security-service
 * so the publish_total metric covers all 3 security topics (SBOM, VULN, RISK).
 */
export async function publishInstrumented(
  bus: EventBus,
  payload: {
    type: string;
    version?: number;
    source: string;
    tenantId: string;
    severity: string;
    data: unknown;
  },
): Promise<unknown> {
  try {
    const result = await bus.publish(payload);
    eventbusPublishTotal.inc(withService({ topic: payload.type, result: 'success' }));
    return result;
  } catch (err) {
    eventbusPublishTotal.inc(withService({ topic: payload.type, result: 'error' }));
    throw err;
  }
}
