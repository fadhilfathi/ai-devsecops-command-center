import { test, expect } from 'vitest';
import { buildServer } from './index.js';

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
