// =============================================================================
// Fastify plugin — common HTTP request metrics + `/metrics` endpoint.
//
// Every AICC backend service calls `registerHttpMetrics(server)` once, right
// after its core plugins (helmet/cors/sensible), to get:
//   - `http_request_duration_seconds{service,method,route,status_code}` (Histogram)
//   - `http_requests_total{service,method,route,status_code}` (Counter)
//   - `GET /metrics` — renders the registry in Prometheus exposition format
//
// `route` is always the matched Fastify route pattern (e.g. `/v1/assets/:id`),
// never the raw URL — this keeps cardinality bounded (no path params, no
// query strings). Unmatched routes (404s) are labelled `unmatched`.
//
// See: docs/observability/metrics-spec.md §5.1 (forbidden labels — no
// tenant_id/user_id/etc. here, consistent with the rest of this package).
// =============================================================================

import type { FastifyInstance } from 'fastify';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

import { defaultRegistry, DEFAULT_LATENCY_BUCKETS, serviceName, renderMetrics } from './metrics.js';

interface HttpMetrics {
  histogram: Histogram<string>;
  counter: Counter<string>;
}

// Per-registry cache: `registerHttpMetrics` may run multiple times against
// the same registry (e.g. once per `buildServer()` call in tests) — reuse
// the already-registered Counter/Histogram instead of re-registering (which
// prom-client throws on).
const httpMetricsByRegistry = new WeakMap<Registry, HttpMetrics>();

// `defaultRegistry` already runs `collectDefaultMetrics` at module load
// (backend/common/observability/metrics.ts), so skip it here to avoid
// double-collecting Node.js process metrics under a second name.
const defaultMetricsCollected = new WeakSet<Registry>([defaultRegistry]);

function getHttpMetrics(registry: Registry): HttpMetrics {
  const existing = httpMetricsByRegistry.get(registry);
  if (existing) return existing;

  const created: HttpMetrics = {
    histogram: new Histogram({
      name: 'http_request_duration_seconds',
      help: 'HTTP request duration, in seconds, labelled by method/route/status_code.',
      labelNames: ['service', 'method', 'route', 'status_code'],
      buckets: DEFAULT_LATENCY_BUCKETS,
      registers: [registry],
    }),
    counter: new Counter({
      name: 'http_requests_total',
      help: 'Total HTTP requests handled, labelled by method/route/status_code.',
      labelNames: ['service', 'method', 'route', 'status_code'],
      registers: [registry],
    }),
  };
  httpMetricsByRegistry.set(registry, created);
  return created;
}

export interface RegisterHttpMetricsOptions {
  /** Override the default registry (mainly for test isolation). */
  registry?: Registry;
  /** Register `GET /metrics` on the server. Default true. */
  exposeRoute?: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    _metricsStartedAt?: number;
  }
}

/**
 * Register the shared HTTP request histogram/counter and (by default) a
 * `GET /metrics` route on `server`.
 */
export function registerHttpMetrics(
  server: FastifyInstance,
  opts: RegisterHttpMetricsOptions = {},
): void {
  const registry = opts.registry ?? defaultRegistry;
  const exposeRoute = opts.exposeRoute ?? true;

  if (!defaultMetricsCollected.has(registry)) {
    collectDefaultMetrics({ register: registry });
    defaultMetricsCollected.add(registry);
  }

  const { histogram, counter } = getHttpMetrics(registry);

  server.addHook('onRequest', async (req) => {
    req._metricsStartedAt = performance.now();
  });

  server.addHook('onResponse', async (req, reply) => {
    const startedAt = req._metricsStartedAt ?? performance.now();
    const durationSeconds = (performance.now() - startedAt) / 1000;
    const route = req.routeOptions?.url ?? 'unmatched';
    const labels = {
      service: serviceName,
      method: req.method,
      route,
      status_code: String(reply.statusCode),
    };
    histogram.observe(labels, durationSeconds);
    counter.inc(labels);
  });

  if (exposeRoute) {
    server.get('/metrics', async (_req, reply) => {
      const { body, contentType } = await renderMetrics(registry);
      reply.header('Content-Type', contentType);
      return body;
    });
  }
}
