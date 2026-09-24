/**
 * Integration Service — entry point.
 *
 * Provides:
 *   - Pluggable provider connectors (GitHub, GitLab, Bitbucket, Jira, Slack)
 *   - Webhook ingestion endpoints with signature verification
 *   - Sync orchestration (PR scanning, SBOM attachment, alerts)
 */
import { pathToFileURL } from 'node:url';
import Fastify, { type FastifyInstance, type FastifyError } from 'fastify';
import { registerHttpMetrics } from '@aicc/observability';
import {
  createLogger,
  loadServiceConfig,
  registerGracefulShutdown,
  registerSecurityPlugins,
  buildAuthHook,
  createEventBus,
  type EventBus,
  type Logger,
} from '@aicc/shared';
import { buildHealthRoutes } from './routes/health.js';
import { buildIntegrationRoutes } from './routes/integrations.js';
import { buildWebhookRoutes } from './routes/webhooks.js';
import { buildIntegrationRepository } from './repositories/integration.repository.js';
import { buildSyncRepository } from './repositories/sync.repository.js';
import { buildProviderRegistry } from './providers/registry.js';

const SERVICE_NAME = 'integration-service';
const SERVICE_VERSION = '0.1.0';

export interface IntegrationServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(
  deps?: Partial<IntegrationServiceDeps>,
): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });

  const integrations = buildIntegrationRepository();
  const syncs = buildSyncRepository();
  const providers = buildProviderRegistry({ bus, logger, syncs });

  const server = Fastify({
    loggerInstance: logger,
    trustProxy: cfg.security.trustProxy,
    bodyLimit: cfg.security.bodyLimitBytes,
    genReqId: () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
  });

  await registerSecurityPlugins(server, cfg);
  registerHttpMetrics(server);

  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');

  server.addHook('onRequest', buildAuthHook({ ...cfg.auth, logger }));

  await server.register(buildHealthRoutes, { logger, cfg, providers, bus });
  await server.register(buildIntegrationRoutes, { logger, integrations, providers });
  await server.register(buildWebhookRoutes, { logger, providers, integrations, syncs, bus });

  server.setErrorHandler<FastifyError>((err, _req, reply) => {
    logger.error({ err }, 'unhandled error');
    if (reply.statusCode < 400) reply.code(err.statusCode ?? 500);
    reply.send({
      code: err.code ?? 'INTERNAL_ERROR',
      message: err.message ?? 'Internal Server Error',
    });
  });

  server.addHook('onClose', async () => {
    await bus.close();
  });

  return server;
}

async function main(): Promise<void> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const server = await buildServer({ logger });
  registerGracefulShutdown(server, logger);
  try {
    await server.listen({ port: cfg.port, host: cfg.host });
    logger.info({ port: cfg.port, host: cfg.host }, `${SERVICE_NAME} listening`);
  } catch (err) {
    logger.error({ err }, 'failed to start');
    process.exit(1);
  }
}

const isMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  void main();
}
