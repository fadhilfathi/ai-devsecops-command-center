/**
 * K8s Health Service — entry point.
 *
 * Consumes inventory from the kubernetes-service (or the in-process
 * fixture provider) and produces per-scope health scores + issues +
 * recommendations.
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
import { buildK8sHealthRoutes } from './routes/k8s-health.js';
import { buildInventoryClient } from './inventory/client.js';
import { buildHealthEngine } from './engine/health-engine.js';

const SERVICE_NAME = 'k8s-health-service';
const SERVICE_VERSION = '0.1.0';

export interface K8sHealthServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<K8sHealthServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });

  const inventory = buildInventoryClient({ logger });
  const engine = buildHealthEngine({ logger });

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

  await server.register(buildHealthRoutes, { logger, cfg });
  await server.register(buildK8sHealthRoutes, { logger, inventory, engine, bus });

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
