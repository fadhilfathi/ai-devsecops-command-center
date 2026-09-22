import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { EventBus, Logger } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  db?: Queryable;
  bus?: EventBus;
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, cfg, db, bus } = opts;
  const startedAt = new Date();

  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/readyz', async (_req, reply) => {
    if (db) {
      try {
        await db.query('SELECT 1');
      } catch (err) {
        logger.error({ err }, 'readyz: postgres check failed');
        return reply.code(503).send({ status: 'not_ready' });
      }
    }
    if (bus?.ping) {
      try {
        await bus.ping();
      } catch (err) {
        logger.error({ err }, 'readyz: event bus check failed');
        return reply.code(503).send({ status: 'not_ready' });
      }
    }
    return {
      status: 'ready',
      service: cfg.name,
      version: cfg.version,
      uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
    };
  });
  server.get('/version', async () => ({
    service: cfg.name,
    version: cfg.version,
    startedAt: startedAt.toISOString(),
  }));
  logger.debug('incident-service health routes registered');
};
