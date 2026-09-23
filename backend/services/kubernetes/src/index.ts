/**
 * Kubernetes Service — entry point.
 *
 * Sprint 4: read-only inventory across every cluster a tenant
 * has onboarded. Backed by the in-process Kubernetes provider
 * abstraction (`./providers/registry.ts`) so the dashboard can
 * be developed against deterministic fixtures; a real
 * `@kubernetes/client-node` adapter is wired in Sprint 5.
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
import { createPool, migrate } from '@aicc/shared/db';
import { buildHealthRoutes } from './routes/health.js';
import { buildKubernetesRoutes } from './routes/kubernetes.js';
import { buildConnectionTestRoutes } from './routes/connection-test.js';
import { buildProviderRegistry } from './providers/registry.js';
import {
  buildClusterRepository,
  buildPgClusterRepository,
} from './repositories/cluster.repository.js';
import { MIGRATIONS, migrateCredentials, reencryptCredentials } from './db/migrations.js';
import { loadCredentialKeyring } from './config.js';

const SERVICE_NAME = 'kubernetes-service';
const SERVICE_VERSION = '0.1.0';

export interface KubernetesServiceDeps {
  bus: EventBus;
  logger: Logger;
}

export async function buildServer(deps?: Partial<KubernetesServiceDeps>): Promise<FastifyInstance> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger =
    deps?.logger ?? createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });

  const credentialKeyring = loadCredentialKeyring(cfg.environment, logger);

  const db = cfg.databaseUrl ? createPool(cfg.databaseUrl) : undefined;
  if (db) {
    await migrate(db, MIGRATIONS);
    if (credentialKeyring) {
      await migrateCredentials(db, credentialKeyring, logger);
      await reencryptCredentials(db, credentialKeyring, logger);
    }
  }
  const clusters = db
    ? buildPgClusterRepository(db, credentialKeyring, logger)
    : buildClusterRepository(credentialKeyring);
  const providers = buildProviderRegistry({ logger, clusters });

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

  await server.register(buildHealthRoutes, { logger, cfg, db });
  await server.register(buildKubernetesRoutes, { logger, clusters, providers, bus });
  await server.register(buildConnectionTestRoutes, { logger, clusters, providers });

  server.setErrorHandler<FastifyError>((err, _req, reply) => {
    logger.error({ err }, 'unhandled error');
    if (reply.statusCode < 400) reply.code(err.statusCode ?? 500);
    reply.send({
      code: err.code ?? 'INTERNAL_ERROR',
      message: err.message ?? 'Internal Server Error',
    });
  });

  if (db) {
    server.addHook('onClose', async () => {
      await db.end();
    });
  }
  server.addHook('onClose', async () => {
    await bus.close();
  });

  return server;
}

async function main(): Promise<void> {
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });
  try {
    const server = await buildServer({ logger });
    registerGracefulShutdown(server, logger);
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
