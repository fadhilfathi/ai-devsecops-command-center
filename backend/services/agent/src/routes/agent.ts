/**
 * Agent routes — list agents, submit a task, poll task status.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EventTypes, NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { AgentRegistry } from '../agents/registry.js';
import type { TaskQueue } from '../services/task-queue.js';

interface Deps {
  logger: Logger;
  registry: AgentRegistry;
  queue: TaskQueue;
  bus: EventBus;
}

const TaskSchema = z.object({
  kind: z.string().min(1),
  payload: z.record(z.unknown()).default({}),
  tenantId: z.string().uuid().optional(),
});

export const buildAgentRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, registry, queue, bus } = opts;

  server.get('/v1/agents', async () => ({
    items: registry.agents().map((a) => ({ id: a.id, name: a.name, description: a.description })),
  }));

  server.post('/v1/agents/tasks', async (req, reply) => {
    const body = TaskSchema.parse(req.body);
    const tenantId: UUID = body.tenantId ?? (req.headers['x-tenant-id'] as string) ?? '';
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'tenantId is required' };
    }
    const task = await queue.enqueue({ kind: body.kind, tenantId, payload: body.payload });
    // Fire-and-forget dispatch; in Sprint 2 this will be a worker loop.
    setImmediate(() => {
      void registry
        .dispatch(task, { bus, queue, logger })
        .catch((err) => logger.error({ err, taskId: task.id }, 'dispatch failed'));
    });
    // Publish request event for observability.
    await bus.publish({
      type: EventTypes.AGENT_TASK_REQUESTED,
      version: 1,
      source: 'agent-service',
      tenantId,
      severity: 'info',
      data: { taskId: task.id, kind: body.kind },
    });
    logger.info({ taskId: task.id, kind: body.kind, tenantId }, 'agent task submitted');
    reply.code(202).send({ task });
  });

  server.get<{ Params: { id: string } }>('/v1/agents/tasks/:id', async (req) => {
    const task = await queue.findById(req.params.id);
    if (!task) throw new NotFoundError('Task', req.params.id);
    return { task };
  });

  server.get('/v1/agents/tasks', async (req) => {
    const tenantId = (req.headers['x-tenant-id'] as string) || undefined;
    const items = await queue.list(tenantId);
    return { items, total: items.length };
  });
};
