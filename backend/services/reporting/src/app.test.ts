import { test, expect } from 'vitest';
import { buildServer } from './index.js';

test('GET /healthz returns ok', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ status: 'ok' });
  await server.close();
});

test('GET /v1/reports/cluster-health without x-tenant-id is rejected', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/reports/cluster-health' });
  expect(res.statusCode).toBe(400);
  await server.close();
});

test('GET /v1/reports/cluster-health with x-tenant-id returns a report', async () => {
  const server = await buildServer();
  const res = await server.inject({
    method: 'GET',
    url: '/v1/reports/cluster-health',
    headers: { 'x-tenant-id': 'tenant-1' },
  });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(typeof body.kind).toBe('string');
  await server.close();
});
