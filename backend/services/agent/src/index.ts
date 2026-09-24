/**
 * Agent Service — entry point.
 *
 * Hosts the AICC Agent: a thin orchestrator that fans out scan /
 * triage / compliance tasks to specialised downstream services and
 * collates their results. The detailed agent topology is defined by
 * the PlatformArchitect in `docs/architecture/agent-topology.md`.
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
import { buildAgentRoutes } from './routes/agent.js';
import { buildAgentRegistry } from './agents/registry.js';
import { buildTaskQueue } from './services/task-queue.js';

const SERVICE_NAME = 'agent-service';
const SERVICE_VERSION = '0.1.0';

export interface AgentServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<AgentServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });
  const queue = buildTaskQueue();
  const registry = buildAgentRegistry({ bus, queue, logger });

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

  await server.register(buildHealthRoutes, { logger, cfg, queue, registry, bus });
  await server.register(buildAgentRoutes, { logger, registry, queue, bus });

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
