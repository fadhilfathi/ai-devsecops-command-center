/**
 * Webhook ingestion — receives events from external providers and
 * dispatches them to the matching provider adapter.
 *
 * Each provider's webhook URL pattern is:
 *   POST /v1/webhooks/:provider
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { UnauthorizedError, type EventBus, type Logger } from '@aicc/shared';
import type { ProviderRegistry } from '../providers/registry.js';
import type { IntegrationRepository } from '../repositories/integration.repository.js';
import type { SyncRepository } from '../repositories/sync.repository.js';

interface Deps {
  logger: Logger;
  providers: ProviderRegistry;
  integrations: IntegrationRepository;
  syncs: SyncRepository;
  bus: EventBus;
}

const EnvelopeSchema = z.object({
  tenantId: z.string().uuid(),
  integrationId: z.string().uuid(),
  type: z.string().min(1),
  payload: z.record(z.unknown()).default({}),
});

export const buildWebhookRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, providers, integrations, syncs, bus } = opts;

  server.post<{ Params: { provider: string } }>(
    '/v1/webhooks/:provider',
    {
      config: { rawBody: true },
    },
    async (req, reply) => {
      const provider = providers.get(req.params.provider);
      if (!provider) {
        reply.code(404);
        return { code: 'NOT_FOUND', message: `unknown provider: ${req.params.provider}` };
      }
      // Fastify exposes the raw body via (req as any).rawBody when config.rawBody=true.
      const raw = (req as unknown as { rawBody?: Buffer }).rawBody;
      if (raw && !provider.verifyWebhookSignature(raw, req.headers as Record<string, string | string[]>)) {
        throw new UnauthorizedError('Invalid webhook signature');
      }
      const body = EnvelopeSchema.parse(req.body);
      const integration = await integrations.findById(body.integrationId, body.tenantId);
      if (!integration) {
        reply.code(404);
        return { code: 'NOT_FOUND', message: 'integration not found' };
      }
      if (!integration.enabled) {
        reply.code(202).send({ accepted: false, reason: 'integration disabled' });
        return;
      }
      await provider.handleEvent(
        { type: body.type, tenantId: body.tenantId, integrationId: body.integrationId, payload: body.payload },
        { bus, logger, syncs },
      );
      await integrations.recordSync(body.integrationId, body.tenantId, new Date().toISOString());
      reply.code(202).send({ accepted: true });
    },
  );

  logger.debug('integration-service webhook routes registered');
};
