/**
 * HTTP helpers shared across services: env loading, port resolution,
 * graceful shutdown signal handling.
 */

import type { FastifyInstance } from 'fastify';
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
}

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
  };
}

function defaultPort(serviceName: string): number {
  const map: Record<string, number> = {
    'auth-service': 4001,
    'agent-service': 4002,
    'security-service': 4003,
    'incident-service': 4004,
    'compliance-service': 4005,
    'integration-service': 4006,
  };
  return map[serviceName] ?? 4000;
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
