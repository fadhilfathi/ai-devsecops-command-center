import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger } from '@aicc/shared';
import type { FindingRepository } from '../repositories/finding.repository.js';

interface Deps {
  logger: Logger;
  findings: FindingRepository;
}

const ListQuerySchema = z.object({
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  status: z.enum(['open', 'triaging', 'in_progress', 'resolved', 'suppressed']).optional(),
});

const UpdateStatusSchema = z.object({
  status: z.enum(['open', 'triaging', 'in_progress', 'resolved', 'suppressed']),
});

export const buildFindingRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, findings } = opts;

  server.get('/v1/findings', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const q = ListQuerySchema.parse(req.query ?? {});
    const items = await findings.list(tenantId, q);
    return { items, total: items.length };
  });

  server.get<{ Params: { id: string } }>('/v1/findings/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const f = await findings.findById(req.params.id, tenantId);
    if (!f) throw new NotFoundError('Finding', req.params.id);
    return { finding: f };
  });

  server.patch<{ Params: { id: string } }>('/v1/findings/:id/status', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = UpdateStatusSchema.parse(req.body);
    const updated = await findings.updateStatus(req.params.id, tenantId, body.status);
    if (!updated) throw new NotFoundError('Finding', req.params.id);
    return { finding: updated };
  });

  logger.debug('security-service finding routes registered');
};
