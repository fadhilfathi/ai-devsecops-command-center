#!/usr/bin/env node
/**
 * End-to-end smoke test for the real docker-compose stack (S7-5).
 *
 * Mints its own HS256 access token (same algorithm as
 * `backend/packages/shared/src/auth/index.ts`'s `signAccessToken` —
 * duplicated here on purpose so this script has zero dependencies and
 * can run against a stack built from any commit), waits for every
 * service's `/healthz`, then hits one representative authenticated
 * route per service plus a couple of negative-auth checks and the
 * frontend nginx proxy.
 *
 * Usage: node scripts/e2e-smoke.mjs
 * Env:   AUTH_JWT_SECRET (required), AUTH_JWT_ISSUER, AUTH_JWT_AUDIENCE,
 *        E2E_HOST (default 127.0.0.1)
 */
import { createHmac } from 'node:crypto';

const HOST = process.env.E2E_HOST ?? '127.0.0.1';
const SECRET = process.env.AUTH_JWT_SECRET;
const ISSUER = process.env.AUTH_JWT_ISSUER ?? 'aicc';
const AUDIENCE = process.env.AUTH_JWT_AUDIENCE ?? 'aicc-api';
const HEALTH_TIMEOUT_MS = 3 * 60_000;
const HEALTH_POLL_MS = 3_000;

// Seeded by auth-service's in-memory user repository
// (backend/services/auth/src/services/user.repository.ts) — using its
// tenant/user id means /v1/auth/me resolves to a real user.
const SEED_TENANT_ID = '00000000-0000-4000-8000-000000000000';
const SEED_USER_ID = '00000000-0000-4000-8000-000000000001';

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

/** Mirrors `signAccessToken` in backend/packages/shared/src/auth/index.ts. */
export function mintAccessToken(claims, { secret, issuer, audience, ttlSeconds = 900 }) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = { ...claims, iss: issuer, aud: audience, iat: now, exp: now + ttlSeconds };
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac('sha256', secret).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

// ---------------------------------------------------------------------------
// Service map: one representative authenticated GET route per backend
// service, verified against backend/services/*/src/routes/*.ts. `ready`
// marks the services whose /readyz does a real Postgres/Redis check
// (see @aicc/shared registerSecurityPlugins callers) — every service has
// /readyz, but only these depend on an external datastore.
// ---------------------------------------------------------------------------
const SERVICES = [
  { name: 'auth', port: 3001, route: '/v1/auth/me', ready: true },
  { name: 'agent', port: 3002, route: '/v1/agents', ready: true },
  { name: 'security', port: 3003, route: '/v1/assets', ready: true },
  { name: 'incident', port: 3004, route: '/v1/incidents', ready: true },
  { name: 'compliance', port: 3005, route: '/v1/controls', ready: true },
  { name: 'integration', port: 3006, route: '/v1/integrations', ready: true },
  { name: 'kubernetes', port: 4006, route: '/v1/kubernetes/clusters', ready: true },
  { name: 'k8s-health', port: 4007, route: '/v1/health/clusters', ready: false },
  { name: 'runtime-security', port: 4008, route: '/v1/runtime-security/risks', ready: false },
  { name: 'inventory', port: 4009, route: '/v1/inventory/assets', ready: false },
  { name: 'cost-intelligence', port: 4010, route: '/v1/cost/analysis', ready: false },
  { name: 'topology', port: 4011, route: '/v1/topology/graph', ready: false },
  { name: 'reporting', port: 4012, route: '/v1/reports', ready: false },
];

const FRONTEND_PORT = 5173;
// A handful of /api/* resources proxied by nginx (frontend/proxy-table.mjs).
const FRONTEND_API_RESOURCES = ['/api/controls', '/api/incidents', '/api/integrations'];

const results = [];
function record(name, check, ok, detail = '') {
  results.push({ name, check, ok, detail });
}

async function waitForHealthy(name, port) {
  const url = `http://${HOST}:${port}/healthz`;
  const deadline = Date.now() + HEALTH_TIMEOUT_MS;
  let lastErr = 'timed out';
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (res.ok) return true;
      lastErr = `HTTP ${res.status}`;
    } catch (err) {
      lastErr = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, HEALTH_POLL_MS));
  }
  record(name, 'healthz', false, lastErr);
  return false;
}

async function main() {
  if (!SECRET) {
    console.error('AUTH_JWT_SECRET is required');
    process.exit(1);
  }

  const token = mintAccessToken(
    {
      sub: SEED_USER_ID,
      email: 'admin@aicc.local',
      role: 'platform_admin',
      tenantId: SEED_TENANT_ID,
    },
    { secret: SECRET, issuer: ISSUER, audience: AUDIENCE, ttlSeconds: 600 },
  );
  const authHeader = { authorization: `Bearer ${token}` };

  // 1. wait for every service to report healthy.
  console.log(
    `Waiting up to ${HEALTH_TIMEOUT_MS / 1000}s for ${SERVICES.length} services + frontend...`,
  );
  const healthy = await Promise.all(SERVICES.map((s) => waitForHealthy(s.name, s.port)));
  await waitForHealthy('frontend', FRONTEND_PORT);
  for (const [i, s] of SERVICES.entries()) {
    if (healthy[i]) record(s.name, 'healthz', true);
  }

  // 2. one authenticated GET route per service.
  for (const s of SERVICES) {
    if (!healthy[SERVICES.indexOf(s)]) continue;
    const url = `http://${HOST}:${s.port}${s.route}`;
    try {
      const res = await fetch(url, { headers: authHeader, signal: AbortSignal.timeout(10_000) });
      const body = await res.json().catch(() => undefined);
      record(s.name, `GET ${s.route}`, res.ok && body !== undefined, `HTTP ${res.status}`);
    } catch (err) {
      record(s.name, `GET ${s.route}`, false, err instanceof Error ? err.message : String(err));
    }
  }

  // 3. /readyz for services wired to Postgres/Redis.
  for (const s of SERVICES.filter((x) => x.ready)) {
    const url = `http://${HOST}:${s.port}/readyz`;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      record(s.name, 'readyz', res.ok, `HTTP ${res.status}`);
    } catch (err) {
      record(s.name, 'readyz', false, err instanceof Error ? err.message : String(err));
    }
  }

  // 4. negative auth: no token, and a wrong-secret token.
  {
    const url = `http://${HOST}:3001/v1/auth/me`;
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      record('auth', 'no token -> 401', res.status === 401, `HTTP ${res.status}`);
    } catch (err) {
      record('auth', 'no token -> 401', false, err instanceof Error ? err.message : String(err));
    }

    const badToken = mintAccessToken(
      { sub: SEED_USER_ID, role: 'platform_admin', tenantId: SEED_TENANT_ID },
      { secret: `${SECRET}-wrong`, issuer: ISSUER, audience: AUDIENCE },
    );
    try {
      const res = await fetch(url, {
        headers: { authorization: `Bearer ${badToken}` },
        signal: AbortSignal.timeout(10_000),
      });
      record('auth', 'wrong secret -> 401', res.status === 401, `HTTP ${res.status}`);
    } catch (err) {
      record(
        'auth',
        'wrong secret -> 401',
        false,
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  // 5. frontend: SPA root + a few /api/* resources through nginx.
  try {
    const res = await fetch(`http://${HOST}:${FRONTEND_PORT}/`, {
      signal: AbortSignal.timeout(10_000),
    });
    const text = await res.text();
    record('frontend', 'GET /', res.ok && text.length > 0, `HTTP ${res.status}`);
  } catch (err) {
    record('frontend', 'GET /', false, err instanceof Error ? err.message : String(err));
  }

  for (const resource of FRONTEND_API_RESOURCES) {
    try {
      const res = await fetch(`http://${HOST}:${FRONTEND_PORT}${resource}`, {
        headers: authHeader,
        signal: AbortSignal.timeout(10_000),
      });
      const body = await res.json().catch(() => undefined);
      record('frontend', `GET ${resource}`, res.ok && body !== undefined, `HTTP ${res.status}`);
    } catch (err) {
      record(
        'frontend',
        `GET ${resource}`,
        false,
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  // ---- report -------------------------------------------------------
  const nameW = Math.max(8, ...results.map((r) => r.name.length));
  const checkW = Math.max(10, ...results.map((r) => r.check.length));
  console.log('\n' + 'name'.padEnd(nameW) + '  ' + 'check'.padEnd(checkW) + '  status  detail');
  let failures = 0;
  for (const r of results) {
    if (!r.ok) failures++;
    console.log(
      r.name.padEnd(nameW) +
        '  ' +
        r.check.padEnd(checkW) +
        '  ' +
        (r.ok ? 'PASS  ' : 'FAIL  ') +
        r.detail,
    );
  }
  console.log(`\n${results.length - failures}/${results.length} checks passed.`);
  process.exit(failures > 0 ? 1 : 0);
}

const isMain = import.meta.url === `file:///${process.argv[1]?.replaceAll('\\', '/')}`;
if (isMain) {
  void main();
}
