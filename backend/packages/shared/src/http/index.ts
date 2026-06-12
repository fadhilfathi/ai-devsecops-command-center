/**
 * HTTP helpers shared across services: env loading, port resolution,
 * graceful shutdown signal handling.
 */

import type { FastifyInstance } from 'fastify';
import type { Logger } from '../logger/index.js';

export interface ServiceConfig {
  name: string;
  version: string;
  port: number;
  host: string;
  environment: string;
  logLevel: string;
}

export function loadServiceConfig(name: string, version: string): ServiceConfig {
  return {
    name,
    version,
    port: Number(process.env.PORT ?? defaultPort(name)),
    host: process.env.HOST ?? '0.0.0.0',
    environment: process.env.NODE_ENV ?? 'development',
    logLevel: process.env.LOG_LEVEL ?? 'info',
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
