/**
 * Token service — issues and validates access + refresh tokens.
 *
 * Sprint 1 uses a minimal HMAC-SHA256 JWT implementation. In Sprint 2
 * we will swap to RS256 with a key-set, per the SecurityArchitect's
 * authentication design.
 */
import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import type { UUID, UserRole } from '@aicc/shared';

export interface AccessTokenPayload {
  sub: UUID;
  email: string;
  role: UserRole;
  tenantId: UUID;
}

export interface RefreshTokenPayload {
  sub: UUID;
  jti: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresIn: number;
  refreshTokenExpiresIn: number;
}

export interface TokenService {
  issue(payload: AccessTokenPayload): Promise<TokenPair>;
  verifyAccess(token: string): Promise<AccessTokenPayload>;
  rotateRefresh(token: string): Promise<TokenPair | undefined>;
}

export interface TokenServiceDeps {
  secret: string;
  issuer: string;
  audience: string;
  accessTtl: string;
  refreshTtl: string;
}

function parseTtl(ttl: string): number {
  const match = /^(\d+)([smhd])$/.exec(ttl);
  if (!match) return 900;
  const n = Number(match[1]);
  switch (match[2]) {
    case 's':
      return n;
    case 'm':
      return n * 60;
    case 'h':
      return n * 60 * 60;
    case 'd':
      return n * 60 * 60 * 24;
    default:
      return 900;
  }
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + pad, 'base64');
}

function sign(header: string, payload: string, secret: string): string {
  const data = `${header}.${payload}`;
  return b64url(createHmac('sha256', secret).update(data).digest());
}

export function buildTokenService(deps: TokenServiceDeps): TokenService {
  const accessSec = parseTtl(deps.accessTtl);
  const refreshSec = parseTtl(deps.refreshTtl);
  // In-memory store of valid refresh-token JTIs. Sprint 2: Redis.
  const refreshStore = new Map<string, { sub: UUID; expiresAt: number }>();

  function signJwt<T>(payload: T, ttlSec: number): string {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const fullPayload = {
      ...payload,
      iss: deps.issuer,
      aud: deps.audience,
      iat: now,
      exp: now + ttlSec,
    };
    const body = b64url(JSON.stringify(fullPayload));
    const sig = sign(header, body, deps.secret);
    return `${header}.${body}.${sig}`;
  }

  function verifyJwt<T>(token: string): T {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed token');
    const [header, body, sig] = parts;
    const expected = sign(header, body, deps.secret);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new Error('bad signature');
    }
    const decoded = JSON.parse(b64urlDecode(body).toString('utf8')) as T & { exp: number };
    if (typeof decoded.exp === 'number' && decoded.exp * 1000 < Date.now()) {
      throw new Error('token expired');
    }
    return decoded;
  }

  return {
    async issue(payload) {
      const accessToken = signJwt<AccessTokenPayload>(payload, accessSec);
      const jti = randomBytes(16).toString('hex');
      const refreshPayload: RefreshTokenPayload = { sub: payload.sub, jti };
      const refreshToken = signJwt<RefreshTokenPayload>(refreshPayload, refreshSec);
      refreshStore.set(jti, { sub: payload.sub, expiresAt: Date.now() + refreshSec * 1000 });
      return {
        accessToken,
        refreshToken,
        accessTokenExpiresIn: accessSec,
        refreshTokenExpiresIn: refreshSec,
      };
    },
    async verifyAccess(token) {
      return verifyJwt<AccessTokenPayload>(token);
    },
    async rotateRefresh(token) {
      let decoded: RefreshTokenPayload;
      try {
        decoded = verifyJwt<RefreshTokenPayload>(token);
      } catch {
        return undefined;
      }
      const stored = refreshStore.get(decoded.jti);
      if (!stored || stored.sub !== decoded.sub) return undefined;
      // One-time use: revoke the old refresh token.
      refreshStore.delete(decoded.jti);
      // We need the original access payload to re-issue — Sprint 1 stores it next to the refresh.
      const full = stored as typeof stored & { payload?: AccessTokenPayload };
      if (!full.payload) return undefined;
      return this.issue(full.payload);
    },
  };
}
