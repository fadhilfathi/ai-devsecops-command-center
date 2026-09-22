/**
 * Auth Service — entry point.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import sensible from '@fastify/sensible';
import { registerHttpMetrics } from '@aicc/observability';
import {
  createLogger,
  loadServiceConfig,
  registerGracefulShutdown,
  createEventBus,
  buildAuthHook,
  type EventBus,
} from '@aicc/shared';
import { loadEnv } from './config.js';
import { buildAuthRoutes } from './routes/auth.js';
import { buildHealthRoutes } from './routes/health.js';
import { buildUserRepository } from './services/user.repository.js';
import { buildTokenService } from './services/token.service.js';

const SERVICE_NAME = 'auth-service';
const SERVICE_VERSION = '0.1.0';

export interface AuthServiceDeps {
  bus: EventBus;
  users: ReturnType<typeof buildUserRepository>;
  tokens: ReturnType<typeof buildTokenService>;
}

export async function buildServer(deps?: Partial<AuthServiceDeps>): Promise<FastifyInstance> {
  const env = loadEnv();
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });

  const bus = deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger });
  const users = deps?.users ?? buildUserRepository();
  const tokens =
    deps?.tokens ??
    buildTokenService({
      secret: cfg.auth.secret,
      issuer: cfg.auth.issuer,
      audience: cfg.auth.audience,
      accessTtl: env.JWT_ACCESS_TTL,
      refreshTtl: env.JWT_REFRESH_TTL,
    });

  const server = Fastify({
    logger: logger,
    disableRequestLogging: false,
    trustProxy: true,
    genReqId: () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
  });

  await server.register(helmet, { contentSecurityPolicy: false });
  await server.register(cors, { origin: true, credentials: true });
  await server.register(sensible);
  registerHttpMetrics(server);

  // Decorate request context for downstream handlers.
  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');

  // dev-login and refresh are how a client gets a token in the first
  // place, so they can't require one.
  server.addHook(
    'onRequest',
    buildAuthHook({
      ...cfg.auth,
      optionalPaths: ['/v1/auth/dev-login', '/v1/auth/refresh'],
      logger,
    }),
  );
  server.addHook('onRequest', async (req) => {
    logger.debug({ tenantId: req.tenantId, userId: req.userId, url: req.url }, 'request');
  });

  await server.register(buildHealthRoutes, { logger, cfg, bus });
  await server.register(buildAuthRoutes, {
    logger,
    users,
    tokens,
    bus,
    environment: cfg.environment,
  });

  server.setErrorHandler((err, _req, reply) => {
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
  const env = loadEnv();
  const cfg = loadServiceConfig(SERVICE_NAME, SERVICE_VERSION);
  const logger = createLogger({ service: cfg.name, version: cfg.version, level: cfg.logLevel });

  const server = await buildServer();
  registerGracefulShutdown(server, logger);

  try {
    await server.listen({ port: cfg.port, host: cfg.host });
    logger.info({ port: cfg.port, host: cfg.host, env: env.NODE_ENV }, `${SERVICE_NAME} listening`);
  } catch (err) {
    logger.error({ err }, 'failed to start');
    process.exit(1);
  }
}

// Run when executed directly (not when imported by tests).
const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
