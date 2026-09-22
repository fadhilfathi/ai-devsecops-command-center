import { test, expect } from 'vitest';
import Fastify from 'fastify';
import { signAccessToken, verifyAccessToken, buildAuthHook } from './index.js';

const opts = { secret: 'test-secret-at-least-16-chars', issuer: 'aicc', audience: 'aicc-api' };
const claims = {
  sub: 'user-1',
  email: 'a@b.com',
  role: 'developer' as const,
  tenantId: 'tenant-1',
};

test('verifyAccessToken accepts a validly signed token', () => {
  const token = signAccessToken(claims, opts);
  const payload = verifyAccessToken(token, opts);
  expect(payload.sub).toBe('user-1');
  expect(payload.tenantId).toBe('tenant-1');
});

test('verifyAccessToken rejects a bad signature', () => {
  const token = signAccessToken(claims, opts);
  const tampered = token.slice(0, -2) + 'xx';
  expect(() => verifyAccessToken(tampered, opts)).toThrow(/signature/i);
});

test('verifyAccessToken rejects an expired token', () => {
  const token = signAccessToken(claims, { ...opts, ttlSeconds: -1 });
  expect(() => verifyAccessToken(token, opts)).toThrow(/expired/i);
});

test('verifyAccessToken rejects wrong issuer', () => {
  const token = signAccessToken(claims, opts);
  expect(() => verifyAccessToken(token, { ...opts, issuer: 'someone-else' })).toThrow(/issuer/i);
});

test('verifyAccessToken rejects wrong audience', () => {
  const token = signAccessToken(claims, opts);
  expect(() => verifyAccessToken(token, { ...opts, audience: 'someone-else' })).toThrow(
    /audience/i,
  );
});

function buildTestServer(hookOpts: Parameters<typeof buildAuthHook>[0]) {
  const server = Fastify();
  server.addHook('onRequest', buildAuthHook(hookOpts));
  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/v1/whoami', async (req) => ({
    tenantId: req.tenantId,
    userId: req.userId,
    userRole: req.userRole,
  }));
  server.setErrorHandler((err, _req, reply) => {
    const statusCode = (err as { statusCode?: number }).statusCode ?? 500;
    reply.code(statusCode).send({ code: (err as { code?: string }).code, message: err.message });
  });
  return server;
}

test('buildAuthHook: missing Authorization header returns 401 when bypass is off', async () => {
  const server = buildTestServer({ ...opts, devBypass: false });
  const res = await server.inject({ method: 'GET', url: '/v1/whoami' });
  expect(res.statusCode).toBe(401);
  await server.close();
});

test('buildAuthHook: valid token sets tenantId/userId/userRole', async () => {
  const server = buildTestServer({ ...opts, devBypass: false });
  const token = signAccessToken(claims, opts);
  const res = await server.inject({
    method: 'GET',
    url: '/v1/whoami',
    headers: { authorization: `Bearer ${token}` },
  });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ tenantId: 'tenant-1', userId: 'user-1', userRole: 'developer' });
  await server.close();
});

test('buildAuthHook: dev bypass trusts x-tenant-id when no token is present', async () => {
  const server = buildTestServer({ ...opts, devBypass: true });
  const res = await server.inject({
    method: 'GET',
    url: '/v1/whoami',
    headers: { 'x-tenant-id': 'legacy-tenant' },
  });
  expect(res.statusCode).toBe(200);
  expect(res.json().tenantId).toBe('legacy-tenant');
  await server.close();
});

test('buildAuthHook: an invalid token is rejected even with bypass on', async () => {
  const server = buildTestServer({ ...opts, devBypass: true });
  const res = await server.inject({
    method: 'GET',
    url: '/v1/whoami',
    headers: { authorization: 'Bearer not-a-real-token' },
  });
  expect(res.statusCode).toBe(401);
  await server.close();
});

test('buildAuthHook: public paths skip auth entirely', async () => {
  const server = buildTestServer({ ...opts, devBypass: false });
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  await server.close();
});
