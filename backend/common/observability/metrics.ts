// =============================================================================
// Prometheus metrics helper — thin wrapper around `prom-client` that
// auto-injects the `service` label (per metrics-spec.md §5.1.1).
//
// Why this exists: the Node.js `prom-client` library does NOT auto-add a
// `service` label the way Python's OTel SDK does via the `service.name`
// resource attribute. This helper closes that gap so Node.js services
// emit the same convention as Python services (and so fleet-wide
// aggregation in Grafana / AlertManager works without a per-service
// recording rule).
//
// Owner: SREEngineer (FullstackEngineer contributed the initial helper
// for Sprint 2 S2.7 proxy-layer metrics).
// See: docs/observability/metrics-spec.md §5, §5.1.1
// =============================================================================

import {
  Counter,
  Histogram,
  Registry,
  collectDefaultMetrics,
} from 'prom-client';

// ---------- Service name resolution (metrics-spec.md §5.1.1) ----------

/** Service name from `OTEL_SERVICE_NAME` env var. Falls back to 'unknown'. */
const _serviceName = process.env.OTEL_SERVICE_NAME ?? 'unknown';

/** Exported so other modules can reference the resolved service name. */
export const serviceName: string = _serviceName;

// ---------- Default registry (per-service isolation) ----------

/**
 * Per-service metrics registry. Each service that imports this module
 * gets its own instance (since `new Registry()` runs once per process).
 * Use the optional `registry` parameter on the factory functions for
 * test isolation or to register on a shared registry.
 */
export const defaultRegistry: Registry = new Registry();

/** Default Node.js process metrics (prefixed `devsecops_node_`). */
collectDefaultMetrics({
  register: defaultRegistry,
  prefix: 'devsecops_node_',
});

// ---------- Cardinality-safe defaults ----------

/**
 * Latency histogram buckets (seconds). Excludes extreme outliers (>=30s);
 * values above this are clamped into `+Inf` and counted as one bucket.
 * Mirrors the Python observability-py module's `LATENCY_BUCKETS`.
 */
export const DEFAULT_LATENCY_BUCKETS: number[] = [
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
];

// ---------- Factory types ----------

export interface CreateCounterOptions<T extends readonly string[]> {
  name: string;
  help: string;
  /** Domain labels (excluding `service`, which is auto-injected). */
  labelNames: T;
  /** Override the default registry. Use for tests or shared registries. */
  registry?: Registry;
}

export interface CreateHistogramOptions<T extends readonly string[]> {
  name: string;
  help: string;
  /** Domain labels (excluding `service`, which is auto-injected). */
  labelNames: T;
  buckets?: number[];
  /** Override the default registry. Use for tests or shared registries. */
  registry?: Registry;
}

// ---------- Factory functions ----------

/**
 * Create a Counter that always carries the `service` label.
 *
 * The caller passes only their domain labels; `service` is auto-injected
 * at construction time. Use `withService({ ... })` at the call site too
 * so the `service` value is supplied on every `inc()`.
 */
export function createCounter<T extends readonly string[]>(
  opts: CreateCounterOptions<T>,
): Counter<string> {
  return new Counter({
    name: opts.name,
    help: opts.help,
    labelNames: ['service', ...opts.labelNames] as string[],
    registers: [opts.registry ?? defaultRegistry],
  });
}

/**
 * Create a Histogram that always carries the `service` label.
 * Default buckets are `DEFAULT_LATENCY_BUCKETS`; override via `buckets`.
 */
export function createHistogram<T extends readonly string[]>(
  opts: CreateHistogramOptions<T>,
): Histogram<string> {
  return new Histogram({
    name: opts.name,
    help: opts.help,
    labelNames: ['service', ...opts.labelNames] as string[],
    buckets: opts.buckets ?? DEFAULT_LATENCY_BUCKETS,
    registers: [opts.registry ?? defaultRegistry],
  });
}

// ---------- Label helper ----------

/**
 * Prepend the resolved `service` label to a user's labels object.
 * Use this for every `counter.inc(...)` / `histogram.observe(...)` call
 * so the `service` value is always supplied.
 *
 * Example:
 * ```ts
 * counter.inc(withService({ route: '/sbom/generate', result: 'success' }));
 * ```
 */
export function withService<T extends Record<string, string | number>>(
  labels: T,
): T & { service: string } {
  return { service: serviceName, ...labels };
}

// ---------- Render helper ----------

/**
 * Render the registry's metrics in Prometheus exposition format.
 * Returns the body (string) and content type
 * (`text/plain; version=0.0.4; charset=utf-8`).
 *
 * Use in a `/metrics` HTTP endpoint:
 * ```ts
 * server.get('/metrics', async (_req, reply) => {
 *   const { body, contentType } = await renderMetrics();
 *   reply.header('Content-Type', contentType);
 *   return body;
 * });
 * ```
 */
export async function renderMetrics(
  registry: Registry = defaultRegistry,
): Promise<{ body: string; contentType: string }> {
  return { body: await registry.metrics(), contentType: registry.contentType };
}

// ---------- Cardinality safety (metrics-spec.md §5.1) ----------

/**
 * Labels forbidden on metrics per metrics-spec.md §5.1 (high-cardinality
 * or PII labels). Use this list in code review or a custom lint rule to
 * catch violations before they reach the registry.
 *
 * FORBIDDEN: tenant_id, user_id, request_id, agent_id, worker_id, trace_id
 * (and any form of them, e.g. tenant_id_hash, user_id_hash, etc.)
 */
export const FORBIDDEN_METRIC_LABELS: readonly string[] = [
  'tenant_id',
  'tenant_id_hash',
  'user_id',
  'user_id_hash',
  'request_id',
  'agent_id',
  'worker_id',
  'trace_id',
  'span_id',
] as const;

/**
 * Assert that a label-name list does not include any forbidden labels.
 * Throws at metric-construction time if it does, so we fail fast.
 */
export function assertNoForbiddenLabels(
  labelNames: readonly string[],
  context: string,
): void {
  const bad = labelNames.filter((l) => FORBIDDEN_METRIC_LABELS.includes(l));
  if (bad.length > 0) {
    throw new Error(
      `[${context}] forbidden metric label(s) per metrics-spec.md §5.1: ${bad.join(', ')}. ` +
        `Use logs (where tenant_id is mandatory) or tracing (where trace_id/span_id are natural) ` +
        `instead. See docs/observability/metrics-spec.md.`,
    );
  }
}
