import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { NotFoundError, type Logger, type UUID } from '@aicc/shared';
import type { IntegrationRepository } from '../repositories/integration.repository.js';
import type { ProviderRegistry } from '../providers/registry.js';

interface Deps {
  logger: Logger;
  integrations: IntegrationRepository;
  providers: ProviderRegistry;
}

const CreateIntegrationSchema = z.object({
  provider: z.enum(['github', 'gitlab', 'bitbucket', 'jira', 'slack']),
  name: z.string().min(1).max(200),
  config: z.record(z.unknown()).default({}),
  enabled: z.boolean().default(true),
});

export const buildIntegrationRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, integrations, providers } = opts;

  server.get('/v1/providers', async () => ({
    items: providers.list().map((p) => ({ id: p.id, name: p.name })),
  }));

  server.get('/v1/integrations', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const items = await integrations.list(tenantId);
    return { items, total: items.length };
  });

  server.post('/v1/integrations', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = CreateIntegrationSchema.parse(req.body);
    if (!providers.get(body.provider)) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: `unknown provider: ${body.provider}` };
    }
    const integration = await integrations.create({ ...body, tenantId: tenantId as UUID });
    reply.code(201).send({ integration });
  });

  server.get<{ Params: { id: string } }>('/v1/integrations/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const i = await integrations.findById(req.params.id, tenantId);
    if (!i) throw new NotFoundError('Integration', req.params.id);
    return { integration: i };
  });

  server.patch<{ Params: { id: string } }>('/v1/integrations/:id/enabled', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = z.object({ enabled: z.boolean() }).parse(req.body);
    const updated = await integrations.setEnabled(req.params.id, tenantId, body.enabled);
    if (!updated) throw new NotFoundError('Integration', req.params.id);
    return { integration: updated };
  });

  server.delete<{ Params: { id: string } }>('/v1/integrations/:id', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const ok = await integrations.remove(req.params.id, tenantId);
    if (!ok) throw new NotFoundError('Integration', req.params.id);
    reply.code(204).send();
  });

  logger.debug('integration-service integration routes registered');
};
