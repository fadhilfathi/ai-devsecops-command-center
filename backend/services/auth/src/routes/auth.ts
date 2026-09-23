/**
 * Auth routes — login, refresh, logout, current-user, user CRUD.
 *
 * Sprint 1 uses email + password-less dev login (POST /dev-login).
 * Real credential-based auth, MFA, and SSO are added in Sprint 2.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import {
  AppError,
  EventTypes,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
  type EventBus,
  type Logger,
  type User,
  type UserRole,
} from '@aicc/shared';
import type { UserRepository } from '../services/user.repository.js';
import type { TokenService } from '../services/token.service.js';

interface Deps {
  logger: Logger;
  users: UserRepository;
  tokens: TokenService;
  bus: EventBus;
  /** Node environment; dev-login is never registered when this is 'production'. */
  environment: string;
}

const LoginSchema = z.object({
  email: z.string().email(),
});

const CreateUserSchema = z.object({
  email: z.string().email(),
  displayName: z.string().min(1).max(120),
  role: z.enum(['platform_admin', 'security_analyst', 'compliance_officer', 'developer', 'viewer']),
  tenantId: z.string().uuid(),
});

export const buildAuthRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, users, tokens, bus, environment } = opts;

  // POST /v1/auth/dev-login  — no credential store exists yet, so this is
  // the only login path (sprint 1). Never registered in production; the
  // token's tenant always comes from the seeded user record, never the
  // client.
  if (environment === 'production') {
    logger.warn('dev-login route disabled: NODE_ENV=production');
  } else {
    logger.warn('dev-login route enabled: password-less login, do not enable in production');
    server.post(
      '/v1/auth/dev-login',
      // Credential-stuffing/brute-force surface — much tighter than the
      // service-wide default (see @aicc/shared registerSecurityPlugins).
      { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
      async (req, reply) => {
        const body = LoginSchema.parse(req.body);
        const user = await users.findByEmail(body.email);
        if (!user) throw new NotFoundError('User', body.email);
        if (!user.active) throw new ForbiddenError('User is inactive');

        const pair = await tokens.issue({
          sub: user.id,
          email: user.email,
          role: user.role,
          tenantId: user.tenantId,
        });

        await bus.publish({
          type: EventTypes.AUTH_USER_LOGGED_IN,
          version: 1,
          source: 'auth-service',
          tenantId: user.tenantId,
          severity: 'info',
          data: { userId: user.id, email: user.email },
        });

        reply.code(200).send({ user, ...pair });
      },
    );
  }

  // POST /v1/auth/refresh
  server.post(
    '/v1/auth/refresh',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = z.object({ refreshToken: z.string() }).parse(req.body);
      const pair = await tokens.rotateRefresh(body.refreshToken);
      if (!pair) throw new UnauthorizedError('Invalid refresh token');
      reply.code(200).send(pair);
    },
  );

  // POST /v1/auth/logout
  server.post('/v1/auth/logout', async (req) => {
    await bus.publish({
      type: EventTypes.AUTH_USER_LOGGED_OUT,
      version: 1,
      source: 'auth-service',
      tenantId: req.tenantId || '',
      severity: 'info',
      data: { userId: req.userId || 'unknown' },
    });
    return { ok: true };
  });

  // GET /v1/auth/me
  server.get('/v1/auth/me', async (req) => {
    if (!req.userId) throw new UnauthorizedError();
    const user = await users.findById(req.userId);
    if (!user) throw new NotFoundError('User', req.userId);
    return { user };
  });

  // GET /v1/users
  server.get('/v1/users', async () => {
    const list = await users.list();
    return { items: list, total: list.length, page: 1, pageSize: list.length };
  });

  // POST /v1/users
  server.post('/v1/users', async (req, reply) => {
    const body = CreateUserSchema.parse(req.body);
    const user = await users.create(body);
    reply.code(201).send({ user });
  });

  // PATCH /v1/users/:id/role
  server.patch<{ Params: { id: string }; Body: { role: UserRole } }>(
    '/v1/users/:id/role',
    async (req) => {
      const body = z.object({ role: CreateUserSchema.shape.role }).parse(req.body);
      const updated = await users.findById(req.params.id);
      if (!updated) throw new NotFoundError('User', req.params.id);
      // In a real impl we'd persist the role change. Sprint 1 only validates.
      logger.info({ userId: updated.id, role: body.role }, 'role change requested');
      return { user: { ...updated, role: body.role as User['role'] } };
    },
  );

  logger.debug('auth routes registered');
};

// Re-export for type-safe use in tests
export type { AppError, User };
