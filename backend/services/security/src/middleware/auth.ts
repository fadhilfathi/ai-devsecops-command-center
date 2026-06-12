/**
 * Authentication middleware.
 *
 * Sprint 2 stub: decodes the JWT from the `Authorization: Bearer ...`
 * header using HS256 (dev) or RS256 (prod) and attaches the decoded
 * user payload to `req.user`. The full canonical auth flow — token
 * issuance, refresh, JWKS, revocation — is owned by the auth-service
 * (see docs/architecture/security-model.md).
 *
 * Sprint 2.1 plan: replace the inline HS256 logic with a call to
 * `@aicc/auth.verifyJwt()` and a JWKS fetch from auth-service.
 */
import type { FastifyInstance, FastifyRequest, onRequestHookHandler } from 'fastify';
import { AppError, type UserRole } from '@aicc/shared';

export interface AuthUser {
  sub: string;
  email?: string;
  role: UserRole;
  tenantId: string;
  raw: Record<string, unknown>;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthUser;
  }
}

function base64UrlDecode(input: string): Buffer {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  return Buffer.from(input.replaceAll('-', '+').replaceAll('_', '/') + pad, 'base64');
}

function base64UrlEncode(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function hmacSha256(key: string, data: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHmac } = require('node:crypto') as typeof import('node:crypto');
  return base64UrlEncode(createHmac('sha256', key).update(data).digest());
}

/**
 * Verify a JWT. For Sprint 2 dev we use HS256. RS256 with JWKS is the
 * Sprint 2.1 production path.
 */
function verifyJwt(token: string, opts: { alg: 'HS256' | 'RS256'; secret?: string; publicKey?: string; issuer: string; audience: string }): AuthUser {
  const parts = token.split('.');
  if (parts.length !== 3) throw new AppError('UNAUTHENTICATED', 'Malformed token');
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createVerify, timingSafeEqual } = require('node:crypto') as typeof import('node:crypto');

  // 1. Verify signature
  if (opts.alg === 'HS256') {
    if (!opts.secret) throw new AppError('INTERNAL_ERROR', 'JWT secret not configured');
    const expected = hmacSha256(opts.secret, `${headerB64}.${payloadB64}`);
    const a = Buffer.from(sigB64);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new AppError('UNAUTHENTICATED', 'Bad signature');
    }
  } else {
    if (!opts.publicKey) throw new AppError('INTERNAL_ERROR', 'JWT public key not configured');
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const ok = verifier.verify(opts.publicKey, base64UrlDecode(sigB64));
    if (!ok) throw new AppError('UNAUTHENTICATED', 'Bad signature');
  }

  // 2. Decode header + payload
  const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8')) as { alg?: string; typ?: string };
  if (header.alg !== opts.alg) throw new AppError('UNAUTHENTICATED', `Unexpected alg: ${header.alg}`);

  const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8')) as Record<string, unknown> & {
    iss?: string; aud?: string | string[]; exp?: number; sub?: string;
    email?: string; role?: UserRole; tenantId?: string;
  };

  if (payload.iss !== opts.issuer) throw new AppError('UNAUTHENTICATED', 'Bad issuer');
  if (Array.isArray(payload.aud) ? !payload.aud.includes(opts.audience) : payload.aud !== opts.audience) {
    throw new AppError('UNAUTHENTICATED', 'Bad audience');
  }
  if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
    throw new AppError('UNAUTHENTICATED', 'Token expired');
  }
  if (!payload.sub || !payload.role || !payload.tenantId) {
    throw new AppError('UNAUTHENTICATED', 'Missing required claims (sub, role, tenantId)');
  }

  return {
    sub: payload.sub,
    email: payload.email,
    role: payload.role,
    tenantId: payload.tenantId,
    raw: payload,
  };
}

/**
 * Build the Fastify `onRequest` hook that authenticates the request.
 * The hook attaches `req.user` if a valid bearer token is present.
 * It does NOT reject unauthenticated requests — that is the job of
 * `requireAuth` / `requireRole` middleware applied per route.
 */
export function buildAuthHook(opts: {
  alg: 'HS256' | 'RS256';
  secret?: string;
  publicKey?: string;
  issuer: string;
  audience: string;
}): onRequestHookHandler {
  return async (req: FastifyRequest) => {
    const header = req.headers.authorization;
    if (!header || !header.toLowerCase().startsWith('bearer ')) return;
    const token = header.slice(7).trim();
    if (!token) return;
    try {
      req.user = verifyJwt(token, opts);
    } catch {
      // Token present but invalid — leave `req.user` unset. The
      // route's `requireAuth` middleware will reject it.
    }
  };
}

/**
 * Strict authentication middleware: reject any request that does not
 * carry a valid `req.user`. Use as a `preHandler` on protected routes.
 */
export async function requireAuth(req: FastifyRequest): Promise<void> {
  if (!req.user) {
    throw new AppError('UNAUTHENTICATED', 'Authentication required');
  }
}

/**
 * Optional auth: if a token is present, validate it; if absent or
 * invalid, just pass through with `req.user` undefined. Useful for
 * GET endpoints that personalize but don't require auth.
 */
export async function optionalAuth(req: FastifyRequest): Promise<void> {
  if (!req.user) return; // already attempted by the onRequest hook
}

/**
 * Helper exported for tests that need to mint dev tokens.
 */
export function signDevJwt(opts: {
  secret: string;
  issuer: string;
  audience: string;
  sub: string;
  email?: string;
  role: UserRole;
  tenantId: string;
  ttlSeconds?: number;
}): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: opts.issuer,
    aud: opts.audience,
    iat: now,
    exp: now + (opts.ttlSeconds ?? 900),
    sub: opts.sub,
    email: opts.email,
    role: opts.role,
    tenantId: opts.tenantId,
  };
  const body = base64UrlEncode(JSON.stringify(payload));
  const sig = hmacSha256(opts.secret, `${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

// Re-export for any consumer that needs Fastify's instance type
export type { FastifyInstance };
