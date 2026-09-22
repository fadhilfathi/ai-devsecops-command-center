import { test, expect } from 'vitest';
import { signAccessToken, AUTH_DEV_DEFAULT_SECRET, EventTypes } from '@aicc/shared';
import { buildServer } from './index.js';

function makeFakeBus() {
  const published: Array<{ type: string; tenantId?: string; data?: unknown }> = [];
  return {
    published,
    publish: async (e: { type: string; tenantId?: string; data?: unknown }) => {
      published.push({ type: e.type, tenantId: e.tenantId, data: e.data });
    },
    subscribe: async () => {},
    close: async () => {},
  };
}

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

test('GET /v1/health/clusters without x-tenant-id is rejected', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/health/clusters' });
  expect(res.statusCode).toBe(400);
  await server.close();
});

test('GET /v1/health/clusters with x-tenant-id returns cluster health scores', async () => {
  const server = await buildServer();
  const res = await server.inject({
    method: 'GET',
    url: '/v1/health/clusters',
    headers: { 'x-tenant-id': 'tenant-1' },
  });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(Array.isArray(body.items)).toBe(true);
  expect(body.total).toBe(body.items.length);
  await server.close();
});

test('GET /v1/health/issues publishes a single batched cluster.health.issue.detected event', async () => {
  const bus = makeFakeBus();
  const server = await buildServer({ bus: bus as never });
  const res = await server.inject({
    method: 'GET',
    url: '/v1/health/issues',
    headers: { 'x-tenant-id': 'tenant-1' },
  });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(body.total).toBeGreaterThan(0);
  expect(bus.published.length).toBe(1);
  expect(bus.published[0].type).toBe(EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED);
  expect(bus.published[0].tenantId).toBe('tenant-1');
  expect((bus.published[0].data as { findings: unknown[] }).findings.length).toBe(body.total);
  await server.close();
});

test('GET /v1/health/clusters without a token is 401 when dev bypass is off', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const res = await server.inject({ method: 'GET', url: '/v1/health/clusters' });
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
      url: '/v1/health/clusters',
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
      { sub: 'user-a', role: 'platform_admin', tenantId: 'tenant-a' },
      tokenOpts,
    );
    const res = await server.inject({
      method: 'GET',
      url: '/v1/health/clusters',
      headers: { authorization: `Bearer ${tokenA}`, 'x-tenant-id': 'tenant-b' },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.every((h: { tenantId: string }) => h.tenantId === 'tenant-a')).toBe(true);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});
