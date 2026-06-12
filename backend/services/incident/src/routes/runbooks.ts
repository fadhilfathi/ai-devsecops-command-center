import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger, type UUID } from '@aicc/shared';
import type { RunbookRepository } from '../repositories/runbook.repository.js';

interface Deps {
  logger: Logger;
  runbooks: RunbookRepository;
}

const StepSchema = z.object({
  order: z.number().int().nonnegative(),
  title: z.string().min(1),
  detail: z.string().min(1),
});

const CreateRunbookSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().min(1),
  steps: z.array(StepSchema).min(1),
  triggers: z.array(z.string()).default([]),
});

export const buildRunbookRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, runbooks } = opts;

  server.get('/v1/runbooks', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const items = await runbooks.list(tenantId);
    return { items, total: items.length };
  });

  server.post('/v1/runbooks', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateRunbookSchema.parse(req.body);
    const runbook = await runbooks.create({ ...body, tenantId: tenantId as UUID });
    reply.code(201).send({ runbook });
  });

  server.get<{ Params: { id: string } }>('/v1/runbooks/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const r = await runbooks.findById(req.params.id, tenantId);
    if (!r) throw new NotFoundError('Runbook', req.params.id);
    return { runbook: r };
  });

  server.delete<{ Params: { id: string } }>('/v1/runbooks/:id', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const ok = await runbooks.remove(req.params.id, tenantId);
    if (!ok) throw new NotFoundError('Runbook', req.params.id);
    reply.code(204).send();
  });

  logger.debug('incident-service runbook routes registered');
};
