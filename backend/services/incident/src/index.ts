/**
 * Incident Service — entry point.
 *
 * Tracks the full incident lifecycle, from creation (often triggered
 * by a `vulnerability.detected` event) to mitigation and post-mortem.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import sensible from '@fastify/sensible';
import {
  createLogger,
  loadServiceConfig,
  registerGracefulShutdown,
  InMemoryEventBus,
  type EventBus,
  type Logger,
} from '@aicc/shared';
import { buildHealthRoutes } from './routes/health.js';
import { buildIncidentRoutes } from './routes/incidents.js';
import { buildRunbookRoutes } from './routes/runbooks.js';
import { buildChainRoutes } from './routes/chains.js';
import { buildIncidentRepository } from './repositories/incident.repository.js';
import { buildRunbookRepository } from './repositories/runbook.repository.js';
import { buildEventListeners } from './listeners/index.js';
import { buildChainRepository } from './correlation/chain.repository.js';
import { buildCorrelationListener } from './listeners/correlation.listener.js';

const SERVICE_NAME = 'incident-service';
const SERVICE_VERSION = '0.1.0';

export interface IncidentServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<IncidentServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? new InMemoryEventBus();

  const incidents = buildIncidentRepository();
  const runbooks = buildRunbookRepository();
  const chains = buildChainRepository();

  const server = Fastify({
    loggerInstance: logger,
    trustProxy: true,
    genReqId: () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
  });

  await server.register(helmet, { contentSecurityPolicy: false });
  await server.register(cors, { origin: true, credentials: true });
  await server.register(sensible);

  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');

  server.addHook('onRequest', async (req) => {
    req.tenantId = (req.headers['x-tenant-id'] as string) ?? '';
    req.userId = (req.headers['x-user-id'] as string) ?? '';
  });

  await server.register(buildHealthRoutes, { logger, cfg });
  await server.register(buildIncidentRoutes, { logger, incidents, bus });
  await server.register(buildRunbookRoutes, { logger, runbooks });
  await server.register(buildChainRoutes, { logger, chains });

  // Wire the in-process event listeners (e.g. auto-open an incident
  // when a critical vulnerability is detected). The same wiring will
  // work against the broker-based bus in Sprint 2.
  await buildEventListeners({ bus, incidents, logger });
  // Sprint 4: the correlation listener feeds every event on the bus
  // through the AI incident correlation engine and persists the
  // resulting chains.
  await buildCorrelationListener({ bus, chains, logger });

  server.setErrorHandler((err, _req, reply) => {
    logger.error({ err }, 'unhandled error');
    if (reply.statusCode < 400) reply.code(err.statusCode ?? 500);
    reply.send({ code: err.code ?? 'INTERNAL_ERROR', message: err.message ?? 'Internal Server Error' });
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

const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
