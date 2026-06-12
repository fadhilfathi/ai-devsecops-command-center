// =============================================================================
// Reference observability implementations for TypeScript/Node.js services.
// Re-exported via the @aicc/observability path mapping in
// backend/tsconfig.base.json.
//
// See: docs/observability/metrics-spec.md, monitoring-architecture.md
//
// Migration note: the current minimal logger lives in
// `backend/packages/shared/src/logger/index.ts`. Migration to this
// @aicc/observability surface is owned by FullstackEngineer per the
// SLO burn-down plan in monitoring-architecture.md §13.
// =============================================================================

// ---------- OpenTelemetry bootstrap ----------
export {
  startOtel,
  shutdownOtel,
  type OtelBootstrapOptions,
} from './otel.js';

// ---------- Structured logging ----------
export {
  createLogger,
  withTenant,
  withUser,
  LogEntrySchema,
  type LoggerConfig,
} from './logger.js';

// ---------- Health checks ----------
export {
  buildHealthServer,
  postgresCheck,
  redisCheck,
  natsCheck,
  type HealthCheck,
  type HealthCheckOptions,
} from './health.js';

// ---------- Metrics helper (Sprint 2 S2.7) ----------
export {
  createCounter,
  createHistogram,
  withService,
  renderMetrics,
  assertNoForbiddenLabels,
  serviceName,
  defaultRegistry,
  DEFAULT_LATENCY_BUCKETS,
  FORBIDDEN_METRIC_LABELS,
  type CreateCounterOptions,
  type CreateHistogramOptions,
} from './metrics.js';
