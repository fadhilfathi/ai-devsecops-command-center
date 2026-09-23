import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import { EventTypes } from '@aicc/shared';
import type { SbomRepository, SbomFormat } from '../repositories/sbom.repository.js';
import type { AssetRepository } from '../repositories/asset.repository.js';

interface Deps {
  logger: Logger;
  sboms: SbomRepository;
  assets: AssetRepository;
  bus: EventBus;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

const CreateSbomSchema = z.object({
  assetId: z.string().uuid(),
  format: z.enum(['cyclonedx', 'spdx']),
  document: z.unknown(),
});

export const buildSbomRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, sboms, assets, bus } = opts;

  server.get('/v1/sboms', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const assetId = (req.query as { assetId?: string }).assetId;
    const items = await sboms.list(tenantId, assetId);
    return { items, total: items.length };
  });

  server.post(
    '/v1/sboms',
    // The raw CycloneDX/SPDX `document` can exceed the shared 1 MiB default.
    { bodyLimit: 10 * 1024 * 1024 },
    async (req, reply) => {
      const tenantId = requireTenant(req.tenantId);
      const body = CreateSbomSchema.parse(req.body);
      const asset = await assets.findById(body.assetId, tenantId);
      if (!asset) throw new NotFoundError('Asset', body.assetId);
      const record = await sboms.create({
        tenantId,
        assetId: body.assetId,
        format: body.format as SbomFormat,
        document: body.document,
      });
      await bus.publish({
        type: EventTypes.INTEGRATION_SYNC_COMPLETED,
        version: 1,
        source: 'security-service',
        tenantId,
        severity: 'info',
        data: {
          kind: 'sbom.created',
          sbomId: record.id,
          assetId: body.assetId,
          format: body.format,
        },
      });
      return reply.code(201).send({ sbom: record });
    },
  );

  server.get<{ Params: { id: string } }>('/v1/sboms/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const s = await sboms.findById(req.params.id, tenantId);
    if (!s) throw new NotFoundError('Sbom', req.params.id);
    return { sbom: s };
  });

  logger.debug('security-service sbom routes registered');
};
