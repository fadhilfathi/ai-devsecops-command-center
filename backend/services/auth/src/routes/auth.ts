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
}

const LoginSchema = z.object({
  email: z.string().email(),
  tenantId: z.string().uuid().optional(),
});

const CreateUserSchema = z.object({
  email: z.string().email(),
  displayName: z.string().min(1).max(120),
  role: z.enum(['platform_admin', 'security_analyst', 'compliance_officer', 'developer', 'viewer']),
  tenantId: z.string().uuid(),
});

export const buildAuthRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, users, tokens, bus } = opts;

  // POST /v1/auth/dev-login  — sprint 1 helper, removed in sprint 2.
  server.post('/v1/auth/dev-login', async (req, reply) => {
    const body = LoginSchema.parse(req.body);
    const user = await users.findByEmail(body.email);
    if (!user) throw new NotFoundError('User', body.email);
    if (!user.active) throw new ForbiddenError('User is inactive');

    const pair = await tokens.issue({
      sub: user.id,
      email: user.email,
      role: user.role,
      tenantId: body.tenantId ?? user.tenantId,
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
  });

  // POST /v1/auth/refresh
  server.post('/v1/auth/refresh', async (req, reply) => {
    const body = z.object({ refreshToken: z.string() }).parse(req.body);
    const pair = await tokens.rotateRefresh(body.refreshToken);
    if (!pair) throw new UnauthorizedError('Invalid refresh token');
    reply.code(200).send(pair);
  });

  // POST /v1/auth/logout
  server.post('/v1/auth/logout', async (req) => {
    const userId = (req.headers['x-user-id'] as string) || 'unknown';
    await bus.publish({
      type: EventTypes.AUTH_USER_LOGGED_OUT,
      version: 1,
      source: 'auth-service',
      tenantId: (req.headers['x-tenant-id'] as string) || '',
      severity: 'info',
      data: { userId },
    });
    return { ok: true };
  });

  // GET /v1/auth/me
  server.get('/v1/auth/me', async (req) => {
    const userId = req.headers['x-user-id'] as string;
    if (!userId) throw new UnauthorizedError();
    const user = await users.findById(userId);
    if (!user) throw new NotFoundError('User', userId);
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
