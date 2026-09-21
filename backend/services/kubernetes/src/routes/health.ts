import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  db?: Queryable;
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, cfg, db } = opts;

  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/livez', async () => ({ status: 'ok' }));
  server.get('/readyz', async (_req, reply) => {
    if (!db) return { status: 'ready' };
    try {
      await db.query('SELECT 1');
      return { status: 'ready' };
    } catch (err) {
      logger.error({ err }, 'readyz: postgres check failed');
      return reply.code(503).send({ status: 'not_ready' });
    }
  });
  server.get('/v1/health', async () => ({
    service: cfg.name,
    version: cfg.version,
    status: 'ok',
    time: new Date().toISOString(),
  }));

  logger.debug('kubernetes-service health routes registered');
};
