/**
 * Zod-validated environment configuration for security-service (S2.5).
 */
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'staging', 'production']).default('development'),
  SERVICE_NAME: z.string().default('security-service'),
  SERVICE_VERSION: z.string().default('0.2.0'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(4003),
  LOG_LEVEL: z.string().default('info'),

  // Downstream Python service URLs (Sprint 2)
  SBOM_PIPELINE_URL: z.string().url().default('http://localhost:4007'),
  VULN_INTEL_URL: z.string().url().default('http://localhost:4008'),
  DEPENDENCY_INTEL_URL: z.string().url().default('http://localhost:4009'),

  // Auth (Sprint 1 stub; Sprint 2.1 will swap to RS256/JWKS via @aicc/auth)
  JWT_ALG: z.enum(['HS256', 'RS256']).default('HS256'),
  JWT_SECRET: z.string().min(16).default('change-me-in-production-please-use-a-long-random-string'),
  JWT_PUBLIC_KEY: z.string().optional(),
  JWT_ISSUER: z.string().default('aicc'),
  JWT_AUDIENCE: z.string().default('aicc-api'),

  // DB
  DATABASE_URL: z.string().url().optional(),

  // Rate limit defaults
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(1000),

  // Event bus
  EVENT_BUS_DRIVER: z.enum(['memory', 'nats', 'redis-streams']).default('memory'),

  // Observability / metrics (S2.7 — security-service :4003 proxy layer)
  /** Master switch for prom-client metric registration. */
  METRICS_ENABLED: z.coerce.boolean().default(true),
  /**
   * OTel-style service name. The `@aicc/observability` helper reads
   * `OTEL_SERVICE_NAME` from `process.env` (default: `service.name`).
   * Set this in production so fleet-wide aggregation works correctly.
   * No `METRICS_TENANT_SALT` — `tenant_id` is forbidden on metrics
   * per metrics-spec.md §5.1.
   */
  OTEL_SERVICE_NAME: z.string().min(1).default('security-service'),
  /** Expose /metrics endpoint. Disable in tests that don't need it. */
  METRICS_EXPOSE_ENDPOINT: z.coerce.boolean().default(true),
});

export type SecurityServiceEnv = z.infer<typeof EnvSchema>;

let cached: SecurityServiceEnv | undefined;

export function loadEnv(): SecurityServiceEnv {
  if (cached) return cached;
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    // eslint-disable-next-line no-console
    console.error('[security-service] invalid environment', parsed.error.flatten());
    throw new Error('Invalid environment configuration for security-service');
  }
  cached = parsed.data;
  return cached;
}
