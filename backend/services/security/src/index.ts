/**
 * Security Service — entry point.
 *
 * Responsibilities:
 *   - Generate and store SBOMs (CycloneDX / SPDX) per asset
 *   - Run vulnerability scanners (Trivy / Grype / Syft) on demand
 *   - Persist scan results and vulnerability findings
 *   - Emit `scan.*` and `vulnerability.detected` events
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
import { buildAssetRoutes } from './routes/assets.js';
import { buildScanRoutes } from './routes/scans.js';
import { buildFindingRoutes } from './routes/findings.js';
import { buildSbomRoutes } from './routes/sbom.js';
import { buildAssetRepository } from './repositories/asset.repository.js';
import { buildScanRepository } from './repositories/scan.repository.js';
import { buildFindingRepository } from './repositories/finding.repository.js';
import { buildSbomRepository } from './repositories/sbom.repository.js';

const SERVICE_NAME = 'security-service';
const SERVICE_VERSION = '0.1.0';

export interface SecurityServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<SecurityServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? new InMemoryEventBus();

  const assets = buildAssetRepository();
  const scans = buildScanRepository();
  const findings = buildFindingRepository();
  const sboms = buildSbomRepository();

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
  await server.register(buildAssetRoutes, { logger, assets });
  await server.register(buildScanRoutes, { logger, assets, scans, findings, bus });
  await server.register(buildFindingRoutes, { logger, findings });
  await server.register(buildSbomRoutes, { logger, sboms, assets, bus });

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
