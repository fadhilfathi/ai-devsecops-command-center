import { test, expect } from 'vitest';
import { signAccessToken, AUTH_DEV_DEFAULT_SECRET } from '@aicc/shared';
import { buildServer } from './index.js';

const tokenOpts = { secret: AUTH_DEV_DEFAULT_SECRET, issuer: 'aicc', audience: 'aicc-api' };

test('GET /healthz returns ok', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ status: 'ok' });
  await server.close();
});

test('GET /metrics returns Prometheus metrics', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/metrics' });
  expect(res.statusCode).toBe(200);
  expect(res.body).toContain('http_requests_total');
  await server.close();
});

test('GET /v1/assets returns an empty catalog without x-tenant-id', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/assets' });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(body).toEqual({ items: [], total: 0 });
  await server.close();
});

test('GET /v1/assets without a token is 401 when dev bypass is off', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const res = await server.inject({ method: 'GET', url: '/v1/assets' });
    expect(res.statusCode).toBe(401);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('a token signed with the wrong secret is rejected', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const token = signAccessToken(
      { sub: 'user-1', role: 'security_analyst', tenantId: 'tenant-a' },
      { ...tokenOpts, secret: 'a-completely-different-secret-value' },
    );
    const res = await server.inject({
      method: 'GET',
      url: '/v1/assets',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(401);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('a token for tenant A plus a forged x-tenant-id header still only sees tenant A data', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const tokenA = signAccessToken(
      { sub: 'user-a', role: 'security_engineer', tenantId: 'tenant-a' },
      tokenOpts,
    );
    await server.inject({
      method: 'POST',
      url: '/v1/assets',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: {
        type: 'repository',
        name: 'tenant-a-repo',
        ownerId: '00000000-0000-4000-8000-000000000099',
      },
    });
    const res = await server.inject({
      method: 'GET',
      url: '/v1/assets',
      headers: { authorization: `Bearer ${tokenA}`, 'x-tenant-id': 'tenant-b' },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.every((a: { tenantId: string }) => a.tenantId === 'tenant-a')).toBe(true);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('GET /security/dashboard authenticates with a real bearer token', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const token = signAccessToken(
      { sub: 'user-1', role: 'security_analyst', tenantId: '00000000-0000-4000-8000-000000000000' },
      tokenOpts,
    );
    const res = await server.inject({
      method: 'GET',
      url: '/security/dashboard',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('security headers: no ACAO on a cross-origin request, strict CSP present', async () => {
  const server = await buildServer();
  const res = await server.inject({
    method: 'GET',
    url: '/healthz',
    headers: { origin: 'https://evil.example' },
  });
  expect(res.headers['access-control-allow-origin']).toBeUndefined();
  expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  await server.close();
});
