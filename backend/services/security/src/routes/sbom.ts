import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import { EventTypes } from '@aicc/shared';
import type { SbomRepository, SbomFormat } from '../repositories/sbom.repository.js';
import type { AssetRepository } from '../repositories/asset.repository.js';
import type { FindingRepository } from '../repositories/finding.repository.js';
import { extractSbomComponents } from '../services/security-analytics.js';

interface Deps {
  logger: Logger;
  sboms: SbomRepository;
  assets: AssetRepository;
  findings: FindingRepository;
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

const SbomIdParamsSchema = z.object({ id: z.string().uuid() });

function parseSbomId(id: string): string {
  const parsed = SbomIdParamsSchema.safeParse({ id });
  if (!parsed.success) {
    const e = new Error(`invalid SBOM id: ${id}`) as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return parsed.data.id;
}

const EXPORT_FORMAT_BY_STORED: Record<SbomFormat, string> = {
  cyclonedx: 'cyclonedx-1.5',
  spdx: 'spdx-2.3',
};

export const buildSbomRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, sboms, assets, findings, bus } = opts;

  // Flat component listing across every SBOM the tenant has (S8-4) — the
  // Sprint-1 "lightweight index" the SBOM page's list view uses. Distinct
  // from `/v1/sboms/:id` (the full per-SBOM document).
  server.get('/v1/sbom/components', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const [records, tenantFindings] = await Promise.all([
      sboms.list(tenantId),
      findings.list(tenantId),
    ]);
    const items = extractSbomComponents(records, tenantFindings);
    return { items, total: items.length };
  });

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
    const id = parseSbomId(req.params.id);
    const s = await sboms.findById(id, tenantId);
    if (!s) throw new NotFoundError('Sbom', id);
    return { sbom: s };
  });

  // S8-4 — serialise the stored document as-is. Only a same-format
  // passthrough is supported (cyclonedx record -> cyclonedx-1.5 export,
  // spdx record -> spdx-2.3 export); converting between the two formats
  // is out of scope here, so a mismatched `format` is a 501.
  server.get<{ Params: { id: string }; Querystring: { format?: string } }>(
    '/v1/sboms/:id/export',
    async (req, reply) => {
      const tenantId = requireTenant(req.tenantId);
      const id = parseSbomId(req.params.id);
      const s = await sboms.findById(id, tenantId);
      if (!s) throw new NotFoundError('Sbom', id);
      const requested = req.query.format ?? EXPORT_FORMAT_BY_STORED[s.format];
      if (requested !== EXPORT_FORMAT_BY_STORED[s.format]) {
        reply.code(501);
        return {
          code: 'NOT_IMPLEMENTED',
          message: `SBOM ${s.id} is stored as ${s.format}; format conversion to ${requested} is not supported`,
        };
      }
      reply.header(
        'content-disposition',
        `attachment; filename="${s.id}.${s.format === 'cyclonedx' ? 'cdx' : 'spdx'}.json"`,
      );
      return s.document;
    },
  );

  logger.debug('security-service sbom routes registered');
};
