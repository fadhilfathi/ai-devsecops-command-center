import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger, type UUID } from '@aicc/shared';
import type { AssetRepository } from '../repositories/asset.repository.js';

interface Deps {
  logger: Logger;
  assets: AssetRepository;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

const CreateAssetSchema = z.object({
  type: z.enum(['repository', 'service', 'container', 'vm', 'saas']),
  name: z.string().min(1).max(200),
  ownerId: z.string().uuid(),
  metadata: z.record(z.string(), z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
});

export const buildAssetRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, assets } = opts;

  server.get('/v1/assets', async (req) => {
    if (!req.tenantId) return { items: [], total: 0 };
    const tenantId = requireTenant(req.tenantId);
    const items = await assets.list(tenantId);
    return { items, total: items.length };
  });

  server.post('/v1/assets', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const body = CreateAssetSchema.parse(req.body);
    const asset = await assets.create({ ...body, tenantId });
    return reply.code(201).send({ asset });
  });

  server.get<{ Params: { id: string } }>('/v1/assets/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const asset = await assets.findById(req.params.id, tenantId);
    if (!asset) throw new NotFoundError('Asset', req.params.id);
    return { asset };
  });

  server.delete<{ Params: { id: string } }>('/v1/assets/:id', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const ok = await assets.remove(req.params.id, tenantId);
    if (!ok) throw new NotFoundError('Asset', req.params.id);
    reply.code(204).send();
  });

  logger.debug('security-service asset routes registered');
};
