/**
 * Shared service-to-service auth: HMAC-SHA256 (HS256) access-token
 * verification and a Fastify `onRequest` hook every service wires in
 * `buildServer()`. Single implementation so no service re-derives the
 * tenant/user identity from a client-supplied header.
 *
 * RS256 + JWKS is a future upgrade (see docs/adr/0013). Everything
 * here intentionally only supports the shared-secret HS256 case.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { FastifyReply, FastifyRequest, onRequestHookHandler } from 'fastify';
import { UnauthorizedError } from '../errors/index.js';
import type { Logger } from '../logger/index.js';
import type { UserRole } from '../types/index.js';

declare module 'fastify' {
  interface FastifyRequest {
    userRole?: UserRole;
  }
}

export interface AccessTokenClaims {
  sub: string;
  email?: string;
  role: UserRole;
  tenantId: string;
}

export interface AccessTokenPayload extends AccessTokenClaims {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

export interface JwtSecretOptions {
  secret: string;
  issuer: string;
  audience: string;
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + pad, 'base64');
}

function sign(header: string, body: string, secret: string): string {
  return b64url(createHmac('sha256', secret).update(`${header}.${body}`).digest());
}

/** Mint an HS256 access token. Used by auth-service on issuance and by tests. */
export function signAccessToken(
  claims: AccessTokenClaims,
  opts: JwtSecretOptions & { ttlSeconds?: number },
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload: AccessTokenPayload = {
    ...claims,
    iss: opts.issuer,
    aud: opts.audience,
    iat: now,
    exp: now + (opts.ttlSeconds ?? 900),
  };
  const body = b64url(JSON.stringify(payload));
  return `${header}.${body}.${sign(header, body, opts.secret)}`;
}

/**
 * Verify an HS256 access token: signature (constant-time compare),
 * expiry, issuer, audience, and required claims. Throws `UnauthorizedError`
 * (401) with a specific message on any failure.
 */
export function verifyAccessToken(token: string, opts: JwtSecretOptions): AccessTokenPayload {
  const parts = token.split('.');
  if (parts.length !== 3) throw new UnauthorizedError('Malformed token');
  const [header, body, sig] = parts as [string, string, string];

  const expected = sign(header, body, opts.secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new UnauthorizedError('Bad signature');
  }

  let decoded: AccessTokenPayload;
  try {
    decoded = JSON.parse(b64urlDecode(body).toString('utf8')) as AccessTokenPayload;
  } catch {
    throw new UnauthorizedError('Malformed token');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof decoded.exp === 'number' && decoded.exp < now) {
    throw new UnauthorizedError('Token expired');
  }
  const nbf = (decoded as AccessTokenPayload & { nbf?: number }).nbf;
  if (typeof nbf === 'number' && nbf > now) {
    throw new UnauthorizedError('Token not yet valid');
  }
  if (decoded.iss !== opts.issuer) throw new UnauthorizedError('Bad issuer');
  const aud = decoded.aud as string | string[];
  const audOk = Array.isArray(aud) ? aud.includes(opts.audience) : aud === opts.audience;
  if (!audOk) throw new UnauthorizedError('Bad audience');
  if (!decoded.sub || !decoded.role || !decoded.tenantId) {
    throw new UnauthorizedError('Missing required claims (sub, role, tenantId)');
  }

  return decoded;
}

const DEFAULT_PUBLIC_PATHS = new Set(['/healthz', '/readyz', '/metrics']);

// Warn once per process, not once per request/service — this is a
// dev/test convenience flag, not something that should spam logs.
let devBypassWarned = false;

export interface AuthHookOptions extends JwtSecretOptions {
  /** Extra paths (exact match, no query string) that skip auth entirely. */
  optionalPaths?: string[];
  /** When true, requests with no Authorization header fall back to trusting `x-tenant-id`/`x-user-id`. Never enable in production. */
  devBypass: boolean;
  logger?: Logger;
  /** Called with a short reason (never the token) whenever a request is rejected. Services wire this to their auth-failure counter. */
  onAuthFailure?: (reason: string) => void;
}

/**
 * Build the `onRequest` hook every service registers. Verifies the
 * bearer token and sets `req.tenantId`/`req.userId`/`req.userRole` from
 * its claims — never from a client-supplied header. Missing/invalid
 * tokens are rejected with 401 unless `devBypass` is enabled, in which
 * case a request with NO Authorization header at all falls back to the
 * legacy `x-tenant-id`/`x-user-id` headers (a present-but-invalid token
 * is always rejected, bypass or not).
 */
export function buildAuthHook(opts: AuthHookOptions): onRequestHookHandler {
  const publicPaths = new Set([...DEFAULT_PUBLIC_PATHS, ...(opts.optionalPaths ?? [])]);

  return async (req: FastifyRequest, _reply: FastifyReply) => {
    const path = (req.routeOptions?.url ?? req.url ?? '').split('?')[0];
    if (publicPaths.has(path)) return;

    const reject = (reason: string): never => {
      opts.onAuthFailure?.(reason);
      opts.logger?.warn({ reason, path }, 'auth rejected');
      throw new UnauthorizedError(reason);
    };

    const header = req.headers.authorization;
    if (header?.toLowerCase().startsWith('bearer ')) {
      const token = header.slice(7).trim();
      let payload: AccessTokenPayload;
      try {
        payload = verifyAccessToken(token, opts);
      } catch (err) {
        reject(err instanceof Error ? err.message : 'Invalid token');
        return;
      }
      req.tenantId = payload.tenantId;
      req.userId = payload.sub;
      req.userRole = payload.role;
      return;
    }

    if (opts.devBypass) {
      if (!devBypassWarned) {
        devBypassWarned = true;
        opts.logger?.warn(
          'AUTH_DEV_BYPASS is enabled: trusting the x-tenant-id/x-user-id headers instead of a verified JWT. Do not enable in production.',
        );
      }
      req.tenantId = (req.headers['x-tenant-id'] as string) ?? '';
      req.userId = (req.headers['x-user-id'] as string) ?? '';
      return;
    }

    reject('Authentication required');
  };
}
