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

const CreateEvidenceSchema = z.object({
  controlId: z.string().uuid(),
  kind: z.enum(['screenshot', 'log', 'config', 'attestation', 'other']),
  description: z.string().min(1),
  ref: z.string().min(1),
});

export const buildEvidenceRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, evidence, controls } = opts;

  server.get('/v1/evidence', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const controlId = (req.query as { controlId?: string }).controlId;
    const items = await evidence.list(tenantId, controlId);
    return { items, total: items.length };
  });

  server.post('/v1/evidence', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const userId = req.headers['x-user-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateEvidenceSchema.parse(req.body);
    const control = await controls.findById(body.controlId, tenantId);
    if (!control) throw new NotFoundError('Control', body.controlId);
    const record = await evidence.create({
      tenantId: tenantId as UUID,
      controlId: body.controlId,
      kind: body.kind,
      description: body.description,
      ref: body.ref,
      collectedBy: (userId || '00000000-0000-4000-8000-000000000000') as UUID,
    });
    // Attach the evidence reference to the control automatically.
    await controls.addEvidence(control.id, tenantId, record.ref);
    reply.code(201).send({ evidence: record });
  });

  server.get<{ Params: { id: string } }>('/v1/evidence/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const e = await evidence.findById(req.params.id, tenantId);
    if (!e) throw new NotFoundError('Evidence', req.params.id);
    return { evidence: e };
  });

  logger.debug('compliance-service evidence routes registered');
};
