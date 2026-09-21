import { test, expect } from 'vitest';
import { buildServer } from './index.js';

test('GET /healthz returns ok', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ status: 'ok' });
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
