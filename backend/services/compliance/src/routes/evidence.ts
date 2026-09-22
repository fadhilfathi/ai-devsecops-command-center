import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger, type UUID } from '@aicc/shared';
import type { EvidenceRepository } from '../repositories/evidence.repository.js';
import type { ControlRepository } from '../repositories/control.repository.js';

interface Deps {
  logger: Logger;
  evidence: EvidenceRepository;
  controls: ControlRepository;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

const CreateEvidenceSchema = z.object({
  controlId: z.string().uuid(),
  kind: z.enum(['screenshot', 'log', 'config', 'attestation', 'other']),
  description: z.string().min(1),
  ref: z.string().min(1),
});

export const buildEvidenceRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, evidence, controls } = opts;

  server.get('/v1/evidence', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const controlId = (req.query as { controlId?: string }).controlId;
    const items = await evidence.list(tenantId, controlId);
    return { items, total: items.length };
  });

  server.post('/v1/evidence', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const userId = req.userId;
    const body = CreateEvidenceSchema.parse(req.body);
    const control = await controls.findById(body.controlId, tenantId);
    if (!control) throw new NotFoundError('Control', body.controlId);
    const record = await evidence.create({
      tenantId,
      controlId: body.controlId,
      kind: body.kind,
      description: body.description,
      ref: body.ref,
      collectedBy: (userId || '00000000-0000-4000-8000-000000000000') as UUID,
    });
    // Attach the evidence reference to the control automatically.
    await controls.addEvidence(control.id, tenantId, record.ref);
    return reply.code(201).send({ evidence: record });
  });

  server.get<{ Params: { id: string } }>('/v1/evidence/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const e = await evidence.findById(req.params.id, tenantId);
    if (!e) throw new NotFoundError('Evidence', req.params.id);
    return { evidence: e };
  });

  logger.debug('compliance-service evidence routes registered');
};
