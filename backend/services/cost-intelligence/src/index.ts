/**
 * Cost Intelligence Service — entry point.
 */
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
import { buildCostRoutes } from './routes/cost.js';
import { buildCostEngine } from './engine/cost.engine.js';
import { buildInventoryClient } from './inventory/client.js';
import {
  buildPrometheusUtilisationSource,
  buildSyntheticUtilisationSource,
} from './utilisation/source.js';

const SERVICE_NAME = 'cost-intelligence-service';
const SERVICE_VERSION = '0.1.0';

export interface CostIntelligenceServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(
  deps?: Partial<CostIntelligenceServiceDeps>,
): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });

  const inventory = buildInventoryClient({ logger, auth: cfg.auth });
  const engine = buildCostEngine({
    cpuUsdPerHour: Number(process.env.AICC_COST_CPU_USD_PER_HOUR ?? 0.041),
    memoryUsdPerHour: Number(process.env.AICC_COST_MEMORY_USD_PER_HOUR ?? 0.005),
  });
  const prometheusUrl = process.env.PROMETHEUS_URL;
  const utilisationSource = prometheusUrl
    ? buildPrometheusUtilisationSource({ baseUrl: prometheusUrl, logger })
    : buildSyntheticUtilisationSource();

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
  await server.register(buildCostRoutes, {
    logger,
    inventory,
    engine,
    bus,
    utilisationSource,
  });

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

const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
