/**
 * HTTP helpers shared across services: env loading, port resolution,
 * graceful shutdown signal handling, and HTTP hardening (CORS/helmet/
 * body limit/rate limit) via `registerSecurityPlugins`.
 */

import type { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import sensible from '@fastify/sensible';
import rateLimit from '@fastify/rate-limit';
import type { Logger } from '../logger/index.js';
import type { EventBusConfig } from '../events/index.js';

// Every service decorates the request with `tenantId`/`userId` from the
// verified access token via the shared `buildAuthHook` `onRequest` hook
// (see `@aicc/shared/auth` and each service's `src/index.ts`) — never
// from a client-supplied header. Declared once here so all services that
// import `@aicc/shared` get the augmented `FastifyRequest` type.
declare module 'fastify' {
  interface FastifyRequest {
    tenantId: string;
    userId: string;
  }
}

export interface ServiceAuthConfig {
  secret: string;
  issuer: string;
  audience: string;
  /** Trust `x-tenant-id`/`x-user-id` headers when no bearer token is present. Never true in production. */
  devBypass: boolean;
}

export interface ServiceSecurityConfig {
  /**
   * Exact browser origins allowed to make cross-origin requests
   * (comma-separated `CORS_ORIGINS`). Empty by default: the SPA talks to
   * every service same-origin through the vite/nginx `/api/*` proxy
   * (see frontend/proxy-table.mjs), so no service needs to reflect a
   * cross-origin `Origin` at all. Never combined with `origin: true` —
   * an allow-list only.
   */
  corsOrigins: string[];
  /** `BODY_LIMIT_BYTES`, default 1 MiB (Fastify's own default). */
  bodyLimitBytes: number;
  /** `RATE_LIMIT_MAX` requests per `RATE_LIMIT_WINDOW` ms, default 300/60s. */
  rateLimitMax: number;
  rateLimitWindowMs: number;
  /**
   * `TRUST_PROXY_CIDR`: comma-separated IP/CIDR list of the only peers
   * whose `X-Forwarded-*` headers Fastify trusts. Fastify 5 removed
   * numeric hop-count trust (it can't validate the immediate peer, so a
   * direct client could spoof it) — an IP/CIDR allow-list is the
   * replacement. Default covers the two ways a request reaches a
   * service: the vite dev proxy on loopback, and nginx inside the
   * `ccnet` docker-compose network (see docker-compose.yml's pinned
   * `172.28.0.0/16` subnet). A client-supplied `X-Forwarded-For` from
   * outside this list is ignored, so it can't spoof the rate-limit key.
   */
  trustProxy: string[];
}

export interface ServiceConfig {
  name: string;
  version: string;
  port: number;
  host: string;
  environment: string;
  logLevel: string;
  /** Postgres connection string. When unset, services fall back to in-memory stores. */
  databaseUrl?: string;
  /** Shared HS256 secret/issuer/audience every service verifies tokens against. */
  auth: ServiceAuthConfig;
  /** `EVENT_BUS_DRIVER` (memory|redis, default memory) + `REDIS_URL`. */
  eventBus: EventBusConfig;
  /** CORS/body-limit/rate-limit knobs for `registerSecurityPlugins`. */
  security: ServiceSecurityConfig;
  /** `AICC_DEMO_SEED=true` makes services insert demo fixture rows on boot (S8-1). Default false. */
  demoSeed: boolean;
  /** Tenant the demo seed writes to. Matches the seeded auth user/e2e smoke tenant. */
  demoTenantId: string;
}

/** Tenant id used by the seeded auth user and `scripts/e2e-smoke.mjs`. */
export const DEMO_TENANT_ID = '00000000-0000-4000-8000-000000000000';

/** Dev-only default secret. Every service refuses to boot with this in production. */
export const AUTH_DEV_DEFAULT_SECRET = 'dev-secret-change-me-please-32-chars-min';

function loadAuthConfig(environment: string): ServiceAuthConfig {
  const secret = process.env.AUTH_JWT_SECRET ?? AUTH_DEV_DEFAULT_SECRET;
  const issuer = process.env.AUTH_JWT_ISSUER ?? 'aicc';
  const audience = process.env.AUTH_JWT_AUDIENCE ?? 'aicc-api';
  const devBypassEnv = process.env.AUTH_DEV_BYPASS;
  const devBypass =
    devBypassEnv !== undefined ? devBypassEnv === 'true' : environment !== 'production';

  if (environment === 'production') {
    if (secret === AUTH_DEV_DEFAULT_SECRET) {
      throw new Error(
        'AUTH_JWT_SECRET must be set to a non-default value in production (refusing to boot with the dev secret)',
      );
    }
    if (secret.length < 32) {
      throw new Error(
        'AUTH_JWT_SECRET must be at least 32 characters in production (refusing to boot with a weak secret)',
      );
    }
  }

  return { secret, issuer, audience, devBypass };
}

function loadEventBusConfig(): EventBusConfig {
  const driver = process.env.EVENT_BUS_DRIVER === 'redis' ? 'redis' : 'memory';
  return { driver, redisUrl: process.env.REDIS_URL };
}

function loadSecurityConfig(): ServiceSecurityConfig {
  const corsOrigins = (process.env.CORS_ORIGINS ?? '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  return {
    corsOrigins,
    bodyLimitBytes: Number(process.env.BODY_LIMIT_BYTES ?? 1_048_576),
    rateLimitMax: Number(process.env.RATE_LIMIT_MAX ?? 300),
    rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW ?? 60_000),
    trustProxy: (process.env.TRUST_PROXY_CIDR ?? '127.0.0.1,172.28.0.0/16')
      .split(',')
      .map((c) => c.trim())
      .filter(Boolean),
  };
}

export function loadServiceConfig(name: string, version: string): ServiceConfig {
  const environment = process.env.NODE_ENV ?? 'development';
  return {
    name,
    version,
    port: Number(process.env.PORT ?? defaultPort(name)),
    host: process.env.HOST ?? '0.0.0.0',
    environment,
    logLevel: process.env.LOG_LEVEL ?? 'info',
    databaseUrl: process.env.DATABASE_URL,
    auth: loadAuthConfig(environment),
    eventBus: loadEventBusConfig(),
    security: loadSecurityConfig(),
    demoSeed: process.env.AICC_DEMO_SEED === 'true',
    demoTenantId: process.env.AICC_DEMO_TENANT_ID ?? DEMO_TENANT_ID,
  };
}

function defaultPort(serviceName: string): number {
  const map: Record<string, number> = {
    'auth-service': 3001,
    'agent-service': 3002,
    'security-service': 3003,
    'incident-service': 3004,
    'compliance-service': 3005,
    'integration-service': 3006,
    'kubernetes-service': 4006,
    'k8s-health-service': 4007,
    'runtime-security-service': 4008,
    'inventory-service': 4009,
    'cost-intelligence-service': 4010,
    'topology-service': 4011,
    'reporting-service': 4012,
  };
  return map[serviceName] ?? 4000;
}

// Health/metrics endpoints are scraped constantly (docker healthchecks,
// Prometheus) — never rate-limited, regardless of the global bucket.
const RATE_LIMIT_EXEMPT_PATHS = new Set(['/healthz', '/readyz', '/metrics']);

// Swagger UI (security-service `/docs`) serves HTML with inline styles/
// scripts — the strict `default-src 'none'` API CSP below would break it.
const SWAGGER_UI_CSP =
  "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'";

export interface RegisterSecurityPluginsOptions {
  /** Path prefixes (e.g. `/docs`) that get the relaxed Swagger UI CSP instead of the strict API default. */
  cspRelaxedPrefixes?: string[];
  /**
   * Skip the shared global rate limit. Only security-service uses this —
   * it registers its own `@fastify/rate-limit` with metrics
   * instrumentation (`rateLimitRejectionsTotal`) and tighter per-route
   * overrides. Default true (every other service gets the shared one).
   */
  installRateLimit?: boolean;
}

/**
 * CORS allow-list + hardened helmet + sensible + a global rate limit —
 * every service calls this once, right after constructing the Fastify
 * instance and before the auth hook/routes (see S7-4 ADR 0018).
 *
 * CORS: no plugin registered (no `access-control-allow-origin` on any
 * response) unless `cfg.security.corsOrigins` is non-empty — the SPA
 * reaches every service same-origin via the vite/nginx `/api/*` proxy,
 * so cross-origin access is opt-in only.
 *
 * Rate limit: keyed by the verified `req.userId` (falls back to `req.ip`
 * for unauthenticated requests). Registered with `hook: 'preHandler'` so
 * it runs after the auth `onRequest` hook every service adds afterwards —
 * `req.userId` is already set by the time the limiter checks it.
 */
export async function registerSecurityPlugins(
  server: FastifyInstance,
  cfg: ServiceConfig,
  opts: RegisterSecurityPluginsOptions = {},
): Promise<void> {
  await server.register(helmet, {
    contentSecurityPolicy: {
      directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
    },
    hsts: { maxAge: 15_552_000, includeSubDomains: true },
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'no-referrer' },
  });

  if (opts.cspRelaxedPrefixes?.length) {
    const prefixes = opts.cspRelaxedPrefixes;
    server.addHook('onSend', async (req, reply, payload) => {
      const path = (req.url ?? '').split('?')[0];
      if (prefixes.some((p) => path === p || path.startsWith(p + '/'))) {
        reply.header('content-security-policy', SWAGGER_UI_CSP);
      }
      return payload;
    });
  }

  if (cfg.security.corsOrigins.length > 0) {
    await server.register(cors, { origin: cfg.security.corsOrigins, credentials: true });
  }

  await server.register(sensible);

  if (opts.installRateLimit ?? true) {
    await server.register(rateLimit, {
      global: true,
      max: cfg.security.rateLimitMax,
      timeWindow: cfg.security.rateLimitWindowMs,
      hook: 'preHandler',
      allowList: (req) => isRateLimitExempt(req.url),
      keyGenerator: (req) => req.userId || req.ip,
      addHeaders: {
        'x-ratelimit-limit': true,
        'x-ratelimit-remaining': true,
        'x-ratelimit-reset': true,
      },
    });
  }
}

/** `/healthz`, `/readyz`, `/metrics` — never rate-limited. Exported so security-service's custom rate-limit registration exempts the same paths. */
export function isRateLimitExempt(url: string | undefined): boolean {
  return RATE_LIMIT_EXEMPT_PATHS.has((url ?? '').split('?')[0]);
}

export function registerGracefulShutdown(server: FastifyInstance, logger: Logger): void {
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  for (const sig of signals) {
    process.once(sig, async () => {
      logger.warn({ signal: sig }, 'shutdown signal received');
      try {
        await server.close();
        logger.info('server closed cleanly');
        process.exit(0);
      } catch (err) {
        logger.error({ err }, 'error during shutdown');
        process.exit(1);
      }
    });
  }
}
