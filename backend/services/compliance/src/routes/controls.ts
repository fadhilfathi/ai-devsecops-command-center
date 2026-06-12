import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EventTypes, NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { ControlRepository } from '../repositories/control.repository.js';

interface Deps {
  logger: Logger;
  controls: ControlRepository;
  bus: EventBus;
}

const CreateControlSchema = z.object({
  framework: z.enum(['cis_v8', 'nist_800_53', 'soc2', 'iso_27001']),
  controlId: z.string().min(1).max(64),
  title: z.string().min(1).max(200),
  description: z.string().min(1),
  evidenceRefs: z.array(z.string()).default([]),
});

const UpdateStatusSchema = z.object({
  status: z.enum(['pass', 'fail', 'not_applicable', 'manual_review']),
});

export const buildControlRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, controls, bus } = opts;

  server.get('/v1/controls', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const framework = (req.query as { framework?: string }).framework as
      | 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001'
      | undefined;
    const items = await controls.list(tenantId, { framework });
    return { items, total: items.length };
  });

  server.post('/v1/controls', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateControlSchema.parse(req.body);
    const control = await controls.create({ ...body, tenantId: tenantId as UUID });
    await bus.publish({
      type: EventTypes.COMPLIANCE_CONTROL_UPDATED,
      version: 1,
      source: 'compliance-service',
      tenantId,
      severity: 'info',
      data: { controlId: control.id, framework: control.framework, status: control.status, kind: 'created' },
    });
    reply.code(201).send({ control });
  });

  server.get<{ Params: { id: string } }>('/v1/controls/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const c = await controls.findById(req.params.id, tenantId);
    if (!c) throw new NotFoundError('Control', req.params.id);
    return { control: c };
  });

  server.patch<{ Params: { id: string } }>('/v1/controls/:id/status', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = UpdateStatusSchema.parse(req.body);
    const updated = await controls.updateStatus(req.params.id, tenantId, body.status);
    if (!updated) throw new NotFoundError('Control', req.params.id);
    await bus.publish({
      type: EventTypes.COMPLIANCE_CONTROL_UPDATED,
      version: 1,
      source: 'compliance-service',
      tenantId,
      severity: body.status === 'fail' ? 'high' : 'info',
      data: { controlId: updated.id, framework: updated.framework, status: body.status, kind: 'status_changed' },
    });
    return { control: updated };
  });

  server.post<{ Params: { id: string } }>('/v1/controls/:id/evidence', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = z.object({ ref: z.string().min(1) }).parse(req.body);
    const updated = await controls.addEvidence(req.params.id, tenantId, body.ref);
    if (!updated) throw new NotFoundError('Control', req.params.id);
    return { control: updated };
  });

  logger.debug('compliance-service control routes registered');
};
