/**
 * Health check routes — liveness & readiness.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { EventBus, Logger } from '@aicc/shared';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  bus?: EventBus;
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, cfg, bus } = opts;
  const startedAt = new Date();

  server.get('/healthz', async () => ({ status: 'ok' }));

  server.get('/readyz', async (_req, reply) => {
    // Sprint 1: minimal readiness. S6-3 added an event-bus (redis) probe.
    if (bus?.ping) {
      try {
        await bus.ping();
      } catch (err) {
        logger.error({ err }, 'readyz: event bus check failed');
        return reply.code(503).send({ status: 'not_ready' });
      }
    }
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
