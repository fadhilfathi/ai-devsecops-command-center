import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';
interface Deps { logger: Logger; cfg: { name: string; version: string } }
export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (server, opts) => {
  const { logger, cfg } = opts;
  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/livez', async () => ({ status: 'ok' }));
  server.get('/readyz', async () => ({ status: 'ready' }));
  server.get('/v1/health', async () => ({ service: cfg.name, version: cfg.version, status: 'ok', time: new Date().toISOString() }));
  logger.debug('topology-service health routes registered');
};
