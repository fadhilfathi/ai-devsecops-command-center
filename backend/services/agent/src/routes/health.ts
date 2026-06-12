import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  queue: { size(): number; list(tenantId?: string): Promise<unknown[]> };
  registry: { agents(): Array<{ id: string; name: string; description: string }> };
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, cfg, queue, registry } = opts;
  const startedAt = new Date();

  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/readyz', async () => ({
    status: 'ready',
    service: cfg.name,
    version: cfg.version,
    uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
    queueDepth: queue.size(),
    registeredAgents: registry.agents().length,
  }));
  server.get('/version', async () => ({ service: cfg.name, version: cfg.version, startedAt: startedAt.toISOString() }));
  logger.debug('agent-service health routes registered');
};
