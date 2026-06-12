# Reference OTel / Logger / Health implementations
#
# These are the SRE-defined TARGET implementations. The current minimal
# versions live in:
#   - backend/packages/shared/src/logger/index.ts   (basic pino wrapper)
#   - backend/services/<svc>/src/routes/health.ts   (basic /healthz + /readyz)
#
# Migration is owned by FullstackEngineer per the SLO burn-down plan in
# docs/observability/monitoring-architecture.md §13.

# otel.ts
Reference OTel SDK bootstrap. Initializes trace, metric, and log exporters
(via OTel Collector), wires auto-instrumentations for HTTP, Fastify, Postgres,
Redis, and NATS, and sets the standard resource attributes
(`service.name`, `service.version`, `deployment.environment`, `service.namespace`).
Excludes the probe endpoints (/livez, /readyz, /startz, /metrics) from tracing
to keep spans focused on user-facing work.

Usage:
```ts
import { startOtel, shutdownOtel } from '@aicc/observability';
startOtel({ service: 'auth', version: '1.0.0', env: 'prod' });
// ... on signal:
await shutdownOtel();
```

# logger.ts
Structured NDJSON logger with:
- Mandatory fields: `service`, `version`, `env`, `tenant_id`.
- W3C trace context propagation (`trace_id`, `span_id`).
- PII redaction at the SDK boundary (emails, phones, JWTs, AWS keys, GitHub
  PATs, private keys). The redaction regex pack is the LAST line of defense;
  the OTel Collector also redacts (`attributes/log_redaction` in
  `infra/observability/otel-collector/collector-config.yaml`).
- JSON schema validation in dev/test; off in prod for throughput.
- 4 KB cap on the `context` payload; 2 KB cap on `message`.

Usage:
```ts
import { createLogger, withTenant, withUser } from '@aicc/observability';
const log = createLogger({ service: 'auth', version: '1.0.0', env: 'prod' });
withTenant(log, 'tenant_42').info({ outcome: 'success' }, 'login completed');
```

# health.ts
Fastify health check server with three probes:
- `/livez` — shallow, never checks dependencies. Use for k8s `livenessProbe`.
- `/readyz` — deep; checks Postgres, Redis, NATS, Vault with per-check timeout
  (default 250 ms). Use for k8s `readinessProbe`.
- `/startz` — returns 503 until the first successful `/readyz`. Use for k8s
  `startupProbe` for slow-init services.

Health check builders are provided for `pg.Pool`, `redis` clients, and NATS
connections. Adding a new dependency is a 10-line change.

Usage:
```ts
import { buildHealthServer, postgresCheck, redisCheck } from '@aicc/observability';
const app = buildHealthServer({
  service: 'auth', version: '1.0.0', startedAt: new Date(),
  checks: [postgresCheck(pool), redisCheck(redis)],
});
await app.listen({ port: 9090, host: '0.0.0.0' });
```
