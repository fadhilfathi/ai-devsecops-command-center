/**
 * Security Service — entry point (S2.5).
 *
 * Sprint 2 responsibilities (extending Sprint 1):
 *   - Sprint 1 surface: /v1/assets, /v1/scans, /v1/findings, /v1/sboms
 *   - Sprint 2 surface (new):
 *       POST /sbom/generate              — proxy to sbom-pipeline-service (4007)
 *       POST /sbom/analyze               — proxy to sbom-pipeline-service (4007)
 *       POST /vulnerabilities/ingest     — proxy to vuln-intel-service (4008)
 *       POST /risk/calculate             — proxy to dependency-intel-service (4009)
 *       GET  /security/dashboard         — aggregate (local)
 *   - OpenAPI / Swagger at /docs
 *   - Per-route rate limit (10 req/s default)
 *   - JWT auth (HS256 Sprint 2 stub, RS256 Sprint 2.1 via @aicc/auth)
 *   - RBAC (platform_admin or security_engineer for POSTs; all auth'd for GETs)
 */
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import sensible from '@fastify/sensible';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { z } from 'zod';

import {
  createLogger,
  loadServiceConfig,
  registerGracefulShutdown,
  InMemoryEventBus,
  type EventBus,
  type Logger,
} from '@aicc/shared';

import { loadEnv } from './config.js';
import { buildAuthHook, requireAuth } from './middleware/auth.js';
import { buildHealthRoutes } from './routes/health.js';
import { buildAssetRoutes } from './routes/assets.js';
import { buildScanRoutes } from './routes/scans.js';
import { buildFindingRoutes } from './routes/findings.js';
import { buildSbomRoutes } from './routes/sbom.js';
import { buildSbomPipelineRoutes } from './routes/sbom-pipeline.js';
import { buildVulnerabilityIngestRoute } from './routes/vulnerabilities-ingest.js';
import { buildRiskCalculateRoute } from './routes/risk.js';
import { buildDashboardRoute } from './routes/dashboard.js';

import { buildAssetRepository } from './repositories/asset.repository.js';
import { buildScanRepository } from './repositories/scan.repository.js';
import { buildFindingRepository } from './repositories/finding.repository.js';
import { buildSbomRepository } from './repositories/sbom.repository.js';
import { InMemoryEventLog } from './services/event-log.js';
import {
  renderMetrics,
  serviceName,
  withService,
  metricsRegistry,
  rateLimitTriggeredTotal,
} from './services/metrics.js';

const SERVICE_NAME = 'security-service';
const SERVICE_VERSION = '0.2.0';

export interface SecurityServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<SecurityServiceDeps>): Promise<FastifyInstance> {
  const env = loadEnv();
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? new InMemoryEventBus();

  const assets = buildAssetRepository();
  const scans = buildScanRepository();
  const findings = buildFindingRepository();
  const sboms = buildSbomRepository();
  const eventLog = new InMemoryEventLog(bus);

  const server = Fastify({
    loggerInstance: logger,
    trustProxy: true,
    genReqId: () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
  });

  // S2.7 — service name is resolved by the @aicc/observability helper
  // at module-load time from OTEL_SERVICE_NAME. Log it for visibility.
  logger.info({ service: serviceName, otel: !!process.env.OTEL_SERVICE_NAME }, 'metrics service name resolved');

  // ---------- Plugins ----------
  await server.register(helmet, { contentSecurityPolicy: false });
  await server.register(cors, { origin: true, credentials: true });
  await server.register(sensible);

  // Global rate limit (10 req/s) — overridden per route where needed.
  // onExceeded hook increments devsecops_rate_limit_triggered_total{route, tenant_id_hash}.
  await server.register(rateLimit, {
    global: true,
    max: env.RATE_LIMIT_MAX,
    timeWindow: env.RATE_LIMIT_WINDOW_MS,
    addHeadersOnExceeding: { 'x-ratelimit-limit': true, 'x-ratelimit-remaining': true, 'x-ratelimit-reset': true },
    addHeaders: { 'x-ratelimit-limit': true, 'x-ratelimit-remaining': true, 'x-ratelimit-reset': true },
    keyGenerator: (req) => req.user?.sub ?? req.ip,
    onExceeded: (req) => {
      const route = req.routeOptions?.url ?? req.url ?? 'unknown';
      // tenantId deliberately NOT a metric label per metrics-spec.md §5.1.
      rateLimitTriggeredTotal.inc(withService({ route }));
    },
  });

  // OpenAPI / Swagger
  await server.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'AICC Security Service API',
        description: 'S2.5 — security API layer. Proxies to sbom-pipeline-service (4007), vuln-intel-service (4008), dependency-intel-service (4009), and aggregates the security dashboard.',
        version: SERVICE_VERSION,
      },
      servers: [{ url: `http://localhost:${env.PORT}`, description: 'Local' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
      tags: [
        { name: 'security', description: 'S2.5 new endpoints' },
        { name: 'sbom', description: 'SBOM proxy endpoints' },
        { name: 'vulnerabilities', description: 'Vulnerability proxy endpoints' },
        { name: 'risk', description: 'Risk calculation proxy endpoints' },
        { name: 'dashboard', description: 'Security dashboard aggregate' },
        { name: 'assets', description: 'Sprint 1: asset inventory' },
        { name: 'scans', description: 'Sprint 1: scan management' },
        { name: 'findings', description: 'Sprint 1: vulnerability findings' },
        { name: 'health', description: 'Health checks' },
      ],
    },
  });
  await server.register(swaggerUi, { routePrefix: '/docs', uiConfig: { docExpansion: 'list' } });

  // ---------- Auth ----------
  server.addHook('preHandler', buildAuthHook({
    alg: env.JWT_ALG,
    secret: env.JWT_SECRET,
    publicKey: env.JWT_PUBLIC_KEY,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
  }));

  // ---------- Request context ----------
  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');
  server.addHook('onRequest', async (req) => {
    req.tenantId = (req.headers['x-tenant-id'] as string) ?? req.user?.tenantId ?? '';
    req.userId = req.user?.sub ?? '';
    logger.debug({ tenantId: req.tenantId, userId: req.userId, url: req.url }, 'request');
  });

  // ---------- Routes ----------
  await server.register(buildHealthRoutes, { logger, cfg });

  // Prometheus metrics endpoint (S2.7) — gated by env flag for tests.
  // Uses the @aicc/observability renderMetrics helper (content-type, body).
  if (env.METRICS_ENABLED && env.METRICS_EXPOSE_ENDPOINT) {
    server.get('/metrics', async (_req, reply) => {
      const { body, contentType } = await renderMetrics(metricsRegistry);
      reply.header('Content-Type', contentType);
      return body;
    });
  }

  // Sprint 1 routes
  await server.register(buildAssetRoutes, { logger, assets });
  await server.register(buildScanRoutes, { logger, assets, scans, findings, bus });
  await server.register(buildFindingRoutes, { logger, findings });
  await server.register(buildSbomRoutes, { logger, sboms, assets, bus });

  // Sprint 2 routes (S2.5)
  await server.register(buildSbomPipelineRoutes, {
    logger,
    bus,
    sbomPipelineUrl: env.SBOM_PIPELINE_URL,
    rateLimitMax: env.RATE_LIMIT_MAX,
    rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
    serviceVersion: SERVICE_VERSION,
  });
  await server.register(buildVulnerabilityIngestRoute, {
    logger,
    bus,
    vulnIntelUrl: env.VULN_INTEL_URL,
    rateLimitMax: env.RATE_LIMIT_MAX,
    rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
    serviceVersion: SERVICE_VERSION,
  });
  await server.register(buildRiskCalculateRoute, {
    logger,
    bus,
    dependencyIntelUrl: env.DEPENDENCY_INTEL_URL,
    rateLimitMax: env.RATE_LIMIT_MAX,
    rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS,
    serviceVersion: SERVICE_VERSION,
  });
  await server.register(buildDashboardRoute, { logger, bus, sboms, scans, findings, eventLog });

  // ---------- Error handler ----------
  server.setErrorHandler((err, req, reply) => {
    logger.error({ err, requestId: req.id, url: req.url }, 'unhandled error');
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    if (reply.statusCode < 400) reply.code(status);
    const code = (err as { code?: string }).code ?? 'INTERNAL_ERROR';
    reply.send({
      code,
      message: err.message ?? 'Internal Server Error',
      ...((err as { details?: unknown }).details ? { details: (err as { details?: unknown }).details } : {}),
      requestId: req.id,
    });
  });

  // Reference unused to keep tree-shake honest
  void requireAuth;
  void z;

  return server;
}

async function main(): Promise<void> {
  const env = loadEnv();
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const server = await buildServer({ logger });
  registerGracefulShutdown(server, logger);
  try {
    await server.listen({ port: cfg.port, host: cfg.host });
    logger.info({ port: cfg.port, host: cfg.host }, `${SERVICE_NAME} listening — docs at /docs`);
  } catch (err) {
    logger.error({ err }, 'failed to start');
    process.exit(1);
  }
}

const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
