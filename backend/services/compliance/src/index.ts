/**
 * Compliance Service — entry point.
 *
 * Owns control mapping (vulnerability → compliance control), evidence
 * attachment, and POA&M (Plan of Action & Milestones) lifecycle.
 */
import Fastify, { type FastifyInstance, type FastifyError } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import sensible from '@fastify/sensible';
import { registerHttpMetrics } from '@aicc/observability';
import {
  createLogger,
  loadServiceConfig,
  registerGracefulShutdown,
  buildAuthHook,
  createEventBus,
  type EventBus,
  type Logger,
} from '@aicc/shared';
import { buildHealthRoutes } from './routes/health.js';
import { buildControlRoutes } from './routes/controls.js';
import { buildEvidenceRoutes } from './routes/evidence.js';
import { buildFrameworkRoutes } from './routes/frameworks.js';
import { buildPoamRoutes } from './routes/poam.js';
import { buildPoamRepository, PoamService } from './poam/index.js';
import { buildControlRepository } from './repositories/control.repository.js';
import { buildFrameworkRepository } from './repositories/framework.repository.js';
import { buildEvidenceRepository } from './repositories/evidence.repository.js';
import { MappingEngine } from './control-mapper/index.js';
import mappingRules from './control-mapper/mapping-rules.json' with { type: 'json' };
import { InMemoryBlobStore } from './evidence/blob-store.memory.js';
import { EvidenceAttacher } from './evidence/evidence-attacher.js';
import { buildScanListener } from './evidence/scan-listener.js';
import { buildInfrastructureListener } from './evidence/infrastructure-listener.js';
import { metricsRegistry } from './observability/audit.js';

const SERVICE_NAME = 'compliance-service';
const SERVICE_VERSION = '0.1.0';

export interface ComplianceServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<ComplianceServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });

  const controls = buildControlRepository();
  const frameworks = buildFrameworkRepository();
  const evidenceRepo = buildEvidenceRepository();
  const poamRepo = buildPoamRepository();
  const poamService = new PoamService({ repo: poamRepo, bus });
  const mappingEngine = new MappingEngine({ rules: mappingRules as never });

  const blobStore = new InMemoryBlobStore();
  const evidenceAttacher = new EvidenceAttacher({
    store: blobStore,
    evidenceRepo,
    mappingEngine,
    poamService,
    bus,
  });

  const server = Fastify({
    loggerInstance: logger,
    trustProxy: true,
    genReqId: () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
  });

  await server.register(helmet, { contentSecurityPolicy: false });
  await server.register(cors, { origin: true, credentials: true });
  await server.register(sensible);
  registerHttpMetrics(server, { registry: metricsRegistry });

  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');

  server.addHook('onRequest', buildAuthHook({ ...cfg.auth, logger }));

  await server.register(buildHealthRoutes, { logger, cfg, bus });
  await server.register(buildControlRoutes, { logger, controls, bus });
  await server.register(buildEvidenceRoutes, { logger, evidence: evidenceRepo, controls });
  await server.register(buildFrameworkRoutes, { logger, frameworks });
  await server.register(buildPoamRoutes, { logger, poamService });

  // Overdue POA&M scanner: hourly tick marks past-due open items as 'overdue'.
  const ONE_HOUR_MS = 60 * 60 * 1000;
  const overdueTimer = setInterval(() => {
    poamService.scanForOverdue().catch((err) => {
      logger.error({ err }, 'overdue_scan_failed');
    });
  }, ONE_HOUR_MS);
  overdueTimer.unref();

  // Bus subscription: attach evidence automatically when a scan completes.
  const scanListener = buildScanListener(evidenceAttacher);
  await bus.subscribe(scanListener.topic, scanListener.handler);

  // Bus subscription: attach evidence automatically for runtime-security
  // and k8s-health findings (S6-4).
  for (const listener of buildInfrastructureListener(evidenceAttacher)) {
    await bus.subscribe(listener.topic, listener.handler);
  }

  server.setErrorHandler<FastifyError>((err, _req, reply) => {
    logger.error({ err }, 'unhandled error');
    if (reply.statusCode < 400) reply.code((err as { statusCode?: number }).statusCode ?? 500);
    reply.send({
      code: (err as { code?: string }).code ?? 'INTERNAL_ERROR',
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

const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
