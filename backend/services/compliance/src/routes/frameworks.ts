import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { Logger } from '@aicc/shared';
import type { FrameworkRepository } from '../repositories/framework.repository.js';

interface Deps {
  logger: Logger;
  frameworks: FrameworkRepository;
}

export const buildFrameworkRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, frameworks } = opts;

  server.get('/v1/frameworks', async (req) => {
    const tenantId = (req.headers['x-tenant-id'] as string) ?? '';
    return { items: await frameworks.list(tenantId) };
  });

  logger.debug('compliance-service framework routes registered');
};
