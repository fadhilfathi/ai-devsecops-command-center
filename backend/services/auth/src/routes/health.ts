/**
 * Health check routes — liveness & readiness.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, cfg } = opts;
  const startedAt = new Date();

  server.get('/healthz', async () => ({ status: 'ok' }));

  server.get('/readyz', async (_req, reply) => {
    // Sprint 1: minimal readiness. Sprint 2 will probe DB / cache / bus.
    const uptime = Math.round((Date.now() - startedAt.getTime()) / 1000);
    return {
      status: 'ready',
      service: cfg.name,
      version: cfg.version,
      uptimeSeconds: uptime,
      checks: {
        process: { status: 'healthy' },
        config: { status: 'healthy' },
      },
    };
  });

  server.get('/version', async () => ({
    service: cfg.name,
    version: cfg.version,
    startedAt: startedAt.toISOString(),
  }));

  logger.debug({ cfg }, 'health routes registered');
};
