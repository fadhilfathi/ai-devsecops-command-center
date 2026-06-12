import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  providers: { list(): Array<{ id: string; name: string }> };
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, cfg, providers } = opts;
  const startedAt = new Date();
  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/readyz', async () => ({
    status: 'ready',
    service: cfg.name,
    version: cfg.version,
    uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
    providers: providers.list().map((p) => p.id),
  }));
  server.get('/version', async () => ({ service: cfg.name, version: cfg.version, startedAt: startedAt.toISOString() }));
  logger.debug('integration-service health routes registered');
};
