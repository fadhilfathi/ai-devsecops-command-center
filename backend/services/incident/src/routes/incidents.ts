import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EventTypes, NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { IncidentRepository } from '../repositories/incident.repository.js';

interface Deps {
  logger: Logger;
  incidents: IncidentRepository;
  bus: EventBus;
}

const CreateIncidentSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().min(1),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  relatedFindingIds: z.array(z.string().uuid()).default([]),
  runbookId: z.string().uuid().optional(),
  assigneeId: z.string().uuid().optional(),
});

const UpdateIncidentSchema = z.object({
  status: z.enum(['open', 'acknowledged', 'mitigating', 'resolved', 'closed']).optional(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  assigneeId: z.string().uuid().optional(),
});

export const buildIncidentRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, incidents, bus } = opts;

  server.get('/v1/incidents', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const status = (req.query as { status?: string }).status as
      | 'open' | 'acknowledged' | 'mitigating' | 'resolved' | 'closed'
      | undefined;
    const items = await incidents.list(tenantId, { status });
    return { items, total: items.length };
  });

  server.post('/v1/incidents', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateIncidentSchema.parse(req.body);
    const incident = await incidents.create({ ...body, tenantId: tenantId as UUID });
    await bus.publish({
      type: EventTypes.INCIDENT_CREATED,
      version: 1,
      source: 'incident-service',
      tenantId,
      severity: incident.severity,
      data: { incidentId: incident.id, title: incident.title, severity: incident.severity },
    });
    reply.code(201).send({ incident });
  });

  server.get<{ Params: { id: string } }>('/v1/incidents/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const i = await incidents.findById(req.params.id, tenantId);
    if (!i) throw new NotFoundError('Incident', req.params.id);
    return { incident: i };
  });

  server.patch<{ Params: { id: string } }>('/v1/incidents/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = UpdateIncidentSchema.parse(req.body);
    const updated = await incidents.update(req.params.id, tenantId, body);
    if (!updated) throw new NotFoundError('Incident', req.params.id);
    if (body.status === 'resolved' || body.status === 'closed') {
      await bus.publish({
        type: EventTypes.INCIDENT_RESOLVED,
        version: 1,
        source: 'incident-service',
        tenantId,
        severity: 'info',
        data: { incidentId: updated.id, finalStatus: body.status },
      });
    }
    logger.info({ incidentId: updated.id, status: updated.status }, 'incident updated');
    return { incident: updated };
  });

  logger.debug('incident-service incident routes registered');
};
