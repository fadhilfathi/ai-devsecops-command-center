import { test, expect, beforeEach, afterEach } from 'vitest';
import Fastify from 'fastify';
import { loadServiceConfig, registerSecurityPlugins } from './index.js';

const ENV_KEYS = [
  'PORT',
  'HOST',
  'NODE_ENV',
  'LOG_LEVEL',
  'AUTH_JWT_SECRET',
  'AUTH_JWT_ISSUER',
  'AUTH_JWT_AUDIENCE',
  'AUTH_DEV_BYPASS',
  'EVENT_BUS_DRIVER',
  'REDIS_URL',
  'CORS_ORIGINS',
  'BODY_LIMIT_BYTES',
  'RATE_LIMIT_MAX',
  'RATE_LIMIT_WINDOW',
  'TRUST_PROXY_CIDR',
  'AICC_DEMO_SEED',
  'AICC_DEMO_TENANT_ID',
] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

test('loadServiceConfig applies defaults when no env is set', () => {
  for (const key of ENV_KEYS) delete process.env[key];
  const cfg = loadServiceConfig('agent-service', '0.1.0');
  expect(cfg).toEqual({
    name: 'agent-service',
    version: '0.1.0',
    port: 4002,
    host: '0.0.0.0',
    environment: 'development',
    logLevel: 'info',
    auth: {
      secret: 'dev-secret-change-me-please-32-chars-min',
      issuer: 'aicc',
      audience: 'aicc-api',
      devBypass: true,
    },
    eventBus: { driver: 'memory', redisUrl: undefined },
    security: {
      corsOrigins: [],
      bodyLimitBytes: 1_048_576,
      rateLimitMax: 300,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
    databaseUrl: undefined,
    demoSeed: false,
    demoTenantId: '00000000-0000-4000-8000-000000000000',
  });
});

test('loadServiceConfig defaults to the redis driver only when EVENT_BUS_DRIVER=redis', () => {
  process.env.EVENT_BUS_DRIVER = 'redis';
  process.env.REDIS_URL = 'redis://localhost:6379';
  const cfg = loadServiceConfig('agent-service', '0.1.0');
  expect(cfg.eventBus).toEqual({ driver: 'redis', redisUrl: 'redis://localhost:6379' });
});

test('loadServiceConfig unknown service defaults to port 4000', () => {
  delete process.env.PORT;
  const cfg = loadServiceConfig('unknown-service', '0.1.0');
  expect(cfg.port).toBe(4000);
});

test('loadServiceConfig honors env var overrides', () => {
  process.env.PORT = '5099';
  process.env.HOST = '127.0.0.1';
  process.env.NODE_ENV = 'production';
  process.env.LOG_LEVEL = 'debug';
  process.env.AUTH_JWT_SECRET = 'a-real-production-secret-not-the-default';
  const cfg = loadServiceConfig('agent-service', '0.1.0');
  expect(cfg.port).toBe(5099);
  expect(cfg.host).toBe('127.0.0.1');
  expect(cfg.environment).toBe('production');
  expect(cfg.logLevel).toBe('debug');
  expect(cfg.auth.devBypass).toBe(false);
});

test('loadServiceConfig refuses the default secret in production', () => {
  process.env.NODE_ENV = 'production';
  delete process.env.AUTH_JWT_SECRET;
  expect(() => loadServiceConfig('agent-service', '0.1.0')).toThrow(/AUTH_JWT_SECRET/);
});

test('loadServiceConfig refuses a short secret in production', () => {
  process.env.NODE_ENV = 'production';
  process.env.AUTH_JWT_SECRET = 'too-short';
  expect(() => loadServiceConfig('agent-service', '0.1.0')).toThrow(/AUTH_JWT_SECRET/);
});

test('loadServiceConfig refuses an empty secret in production', () => {
  process.env.NODE_ENV = 'production';
  process.env.AUTH_JWT_SECRET = '';
  expect(() => loadServiceConfig('agent-service', '0.1.0')).toThrow(/AUTH_JWT_SECRET/);
});

async function buildTestServer(
  cfgOverrides: Partial<ReturnType<typeof loadServiceConfig>> = {},
  opts: Parameters<typeof registerSecurityPlugins>[2] = {},
) {
  const cfg = { ...loadServiceConfig('agent-service', '0.1.0'), ...cfgOverrides };
  // bodyLimit and trustProxy are Fastify constructor options, not something
  // a plugin can apply after the fact — every real service passes both
  // here too (see e.g. backend/services/agent/src/index.ts).
  const server = Fastify({
    bodyLimit: cfg.security.bodyLimitBytes,
    trustProxy: cfg.security.trustProxy,
  });
  await registerSecurityPlugins(server, cfg, opts);
  // Real services decorate + set `req.userId` from a verified bearer token
  // via `buildAuthHook` (@aicc/shared/auth). Simulate the same shape here
  // — `Authorization: Bearer <userId>` sets `req.userId` to `<userId>` —
  // without pulling in the full JWT auth flow, since these tests only
  // exercise `registerSecurityPlugins`'s keyGenerator.
  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');
  server.addHook('onRequest', async (req) => {
    const auth = req.headers.authorization;
    req.userId = auth?.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
  });
  server.get('/thing', async () => ({ ok: true }));
  server.get('/whoami', async (req) => ({ ip: req.ip }));
  server.get('/docs', async () => ({ ok: true }));
  server.get('/docsevil', async () => ({ ok: true }));
  server.get('/healthz', async () => ({ ok: true }));
  server.post('/echo', async (req) => ({ len: JSON.stringify(req.body).length }));
  await server.ready();
  return server;
}

test('registerSecurityPlugins: cross-origin request with no allow-list gets no ACAO header', async () => {
  const server = await buildTestServer();
  const res = await server.inject({
    method: 'GET',
    url: '/thing',
    headers: { origin: 'https://evil.example' },
  });
  expect(res.headers['access-control-allow-origin']).toBeUndefined();
  await server.close();
});

test('registerSecurityPlugins: allow-listed origin gets ACAO echoed back', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: ['https://app.example'],
      bodyLimitBytes: 1_048_576,
      rateLimitMax: 300,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const res = await server.inject({
    method: 'GET',
    url: '/thing',
    headers: { origin: 'https://app.example' },
  });
  expect(res.headers['access-control-allow-origin']).toBe('https://app.example');
  await server.close();
});

test('registerSecurityPlugins: cspRelaxedPrefixes only matches the prefix or a subpath, not a longer path segment', async () => {
  const server = await buildTestServer({}, { cspRelaxedPrefixes: ['/docs'] });
  const docs = await server.inject({ method: 'GET', url: '/docs' });
  expect(docs.headers['content-security-policy']).toContain('script-src');

  const docsSubpath = await server.inject({ method: 'GET', url: '/docs/swagger.json?x=1' });
  expect(docsSubpath.headers['content-security-policy']).toContain('script-src');

  // `/docsevil` starts with the string `/docs` but is not the prefix path
  // nor a subpath of it — must get the strict default CSP, not the
  // relaxed Swagger UI one.
  const evil = await server.inject({ method: 'GET', url: '/docsevil' });
  expect(evil.headers['content-security-policy']).toContain("default-src 'none'");
  await server.close();
});

test('registerSecurityPlugins: strict API CSP and security headers on a normal response', async () => {
  const server = await buildTestServer();
  const res = await server.inject({ method: 'GET', url: '/thing' });
  expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  expect(res.headers['x-content-type-options']).toBe('nosniff');
  expect(res.headers['strict-transport-security']).toBeDefined();
  await server.close();
});

test('registerSecurityPlugins: body over the configured limit gets 413', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: [],
      bodyLimitBytes: 20,
      rateLimitMax: 300,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const res = await server.inject({
    method: 'POST',
    url: '/echo',
    payload: { data: 'x'.repeat(100) },
  });
  expect(res.statusCode).toBe(413);
  await server.close();
});

test('registerSecurityPlugins: rate limit returns 429 after max, healthz is exempt', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: [],
      bodyLimitBytes: 1_048_576,
      rateLimitMax: 1,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const first = await server.inject({ method: 'GET', url: '/thing' });
  expect(first.statusCode).toBe(200);
  const second = await server.inject({ method: 'GET', url: '/thing' });
  expect(second.statusCode).toBe(429);

  const health1 = await server.inject({ method: 'GET', url: '/healthz' });
  const health2 = await server.inject({ method: 'GET', url: '/healthz' });
  expect(health1.statusCode).toBe(200);
  expect(health2.statusCode).toBe(200);
  await server.close();
});

// S7-4: an untrusted peer (outside TRUST_PROXY_CIDR) cannot spoof its
// X-Forwarded-For to rotate the rate-limit key — Fastify's trustProxy
// allow-list must ignore the header entirely for such a peer.
test('registerSecurityPlugins: untrusted peer spoofing X-Forwarded-For is ignored', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: [],
      bodyLimitBytes: 1_048_576,
      // 3, not 2: the /whoami IP-check request below shares the same
      // rate-limit key/bucket as the /thing requests that follow.
      rateLimitMax: 3,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const untrustedIp = '203.0.113.5';

  const whoami = await server.inject({
    method: 'GET',
    url: '/whoami',
    remoteAddress: untrustedIp,
    headers: { 'x-forwarded-for': '1.2.3.4' },
  });
  expect(JSON.parse(whoami.body).ip).toBe(untrustedIp);

  const first = await server.inject({
    method: 'GET',
    url: '/thing',
    remoteAddress: untrustedIp,
    headers: { 'x-forwarded-for': '9.9.9.9' },
  });
  const second = await server.inject({
    method: 'GET',
    url: '/thing',
    remoteAddress: untrustedIp,
    headers: { 'x-forwarded-for': '8.8.8.8' },
  });
  expect(first.statusCode).toBe(200);
  expect(second.statusCode).toBe(200);

  // Budget exhausted (max=3, one already spent by /whoami above) — a 4th
  // request with yet another forged XFF
  // still hits the same bucket because the header is never trusted.
  const third = await server.inject({
    method: 'GET',
    url: '/thing',
    remoteAddress: untrustedIp,
    headers: { 'x-forwarded-for': '7.7.7.7' },
  });
  expect(third.statusCode).toBe(429);
  await server.close();
});

// S7-4: a peer inside TRUST_PROXY_CIDR (nginx's compose-network address) is
// the one case where X-Forwarded-For is honoured — req.ip becomes the
// client IP nginx forwarded, not nginx's own address.
test('registerSecurityPlugins: trusted proxy peer has its X-Forwarded-For honoured', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: [],
      bodyLimitBytes: 1_048_576,
      rateLimitMax: 300,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const res = await server.inject({
    method: 'GET',
    url: '/whoami',
    remoteAddress: '172.28.0.10',
    headers: { 'x-forwarded-for': '198.51.100.7' },
  });
  expect(JSON.parse(res.body).ip).toBe('198.51.100.7');
  await server.close();
});

// S7-4: the rate limit is keyed by the verified userId first, IP only as a
// fallback — two different authenticated users sharing one IP must not
// share one budget.
test('registerSecurityPlugins: authenticated users are keyed by userId, not shared IP', async () => {
  const server = await buildTestServer({
    security: {
      corsOrigins: [],
      bodyLimitBytes: 1_048_576,
      rateLimitMax: 1,
      rateLimitWindowMs: 60_000,
      trustProxy: ['127.0.0.1', '172.28.0.0/16'],
    },
  });
  const sameIp = { remoteAddress: '203.0.113.9' };

  const userA1 = await server.inject({
    method: 'GET',
    url: '/thing',
    ...sameIp,
    headers: { authorization: 'Bearer user-a' },
  });
  const userA2 = await server.inject({
    method: 'GET',
    url: '/thing',
    ...sameIp,
    headers: { authorization: 'Bearer user-a' },
  });
  expect(userA1.statusCode).toBe(200);
  expect(userA2.statusCode).toBe(429); // user A's own budget (max=1) is spent

  const userB1 = await server.inject({
    method: 'GET',
    url: '/thing',
    ...sameIp,
    headers: { authorization: 'Bearer user-b' },
  });
  expect(userB1.statusCode).toBe(200); // user B has an independent budget
  await server.close();
});
