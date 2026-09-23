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

test('GET /v1/users returns the user list', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/users' });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(Array.isArray(body.items)).toBe(true);
  await server.close();
});

test('GET /v1/auth/me without x-user-id is unauthenticated', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/auth/me' });
  expect(res.statusCode).toBe(401);
  await server.close();
});

test('GET /v1/users without a token is 401 when dev bypass is off', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const res = await server.inject({ method: 'GET', url: '/v1/users' });
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
      { sub: 'user-1', role: 'platform_admin', tenantId: 'tenant-a' },
      { ...tokenOpts, secret: 'a-completely-different-secret-value' },
    );
    const res = await server.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(401);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('a valid token plus a forged x-tenant-id header still resolves the token owner only', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const login = await server.inject({
      method: 'POST',
      url: '/v1/auth/dev-login',
      payload: { email: 'admin@aicc.local' },
    });
    const { accessToken } = login.json();
    const res = await server.inject({
      method: 'GET',
      url: '/v1/auth/me',
      headers: { authorization: `Bearer ${accessToken}`, 'x-tenant-id': 'some-other-tenant' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().user.email).toBe('admin@aicc.local');
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('POST /v1/auth/dev-login issues a token that authenticates /v1/auth/me', async () => {
  const server = await buildServer();
  const login = await server.inject({
    method: 'POST',
    url: '/v1/auth/dev-login',
    payload: { email: 'admin@aicc.local' },
  });
  expect(login.statusCode).toBe(200);
  const { accessToken } = login.json();

  const me = await server.inject({
    method: 'GET',
    url: '/v1/auth/me',
    headers: { authorization: `Bearer ${accessToken}` },
  });
  expect(me.statusCode).toBe(200);
  expect(me.json().user.email).toBe('admin@aicc.local');
  await server.close();
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
