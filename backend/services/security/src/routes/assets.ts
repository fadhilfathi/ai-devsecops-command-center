import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger, type UUID } from '@aicc/shared';
import type { AssetRepository } from '../repositories/asset.repository.js';

interface Deps {
  logger: Logger;
  assets: AssetRepository;
}

const CreateAssetSchema = z.object({
  type: z.enum(['repository', 'service', 'container', 'vm', 'saas']),
  name: z.string().min(1).max(200),
  ownerId: z.string().uuid(),
  metadata: z.record(z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
});

export const buildAssetRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, assets } = opts;

  server.get('/v1/assets', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) return { items: [], total: 0 };
    const items = await assets.list(tenantId);
    return { items, total: items.length };
  });

  server.post('/v1/assets', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateAssetSchema.parse(req.body);
    const asset = await assets.create({ ...body, tenantId: tenantId as UUID });
    reply.code(201).send({ asset });
  });

  server.get<{ Params: { id: string } }>('/v1/assets/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const asset = await assets.findById(req.params.id, tenantId);
    if (!asset) throw new NotFoundError('Asset', req.params.id);
    return { asset };
  });

  server.delete<{ Params: { id: string } }>('/v1/assets/:id', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const ok = await assets.remove(req.params.id, tenantId);
    if (!ok) throw new NotFoundError('Asset', req.params.id);
    reply.code(204).send();
  });

  logger.debug('security-service asset routes registered');
};
