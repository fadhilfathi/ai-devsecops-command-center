/**
 * Compliance Service — entry point.
 *
 * Maintains the mapping of organisational assets to compliance
 * controls (CIS v8, NIST 800-53, SOC 2, ISO 27001), stores evidence,
 * and supports audit reporting. The framework → control catalogue
 * is owned by the ComplianceOfficer agent.
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
import { buildControlRoutes } from './routes/controls.js';
import { buildEvidenceRoutes } from './routes/evidence.js';
import { buildFrameworkRoutes } from './routes/frameworks.js';
import { buildControlRepository } from './repositories/control.repository.js';
import { buildEvidenceRepository } from './repositories/evidence.repository.js';
import { buildFrameworkRepository } from './repositories/framework.repository.js';

const SERVICE_NAME = 'compliance-service';
const SERVICE_VERSION = '0.1.0';

export interface ComplianceServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<ComplianceServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? new InMemoryEventBus();

  const controls = buildControlRepository();
  const evidence = buildEvidenceRepository();
  const frameworks = buildFrameworkRepository();

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
  await server.register(buildFrameworkRoutes, { logger, frameworks });
  await server.register(buildControlRoutes, { logger, controls, bus });
  await server.register(buildEvidenceRoutes, { logger, evidence, controls });

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
