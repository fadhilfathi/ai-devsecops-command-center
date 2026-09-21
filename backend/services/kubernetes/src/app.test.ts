import { test, expect } from 'vitest';
import { buildServer } from './index.js';

test('GET /healthz returns ok', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ status: 'ok' });
  await server.close();
});

test('GET /v1/kubernetes/providers lists available providers', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/kubernetes/providers' });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(Array.isArray(body.items)).toBe(true);
  await server.close();
});

test('GET /v1/kubernetes/clusters without x-tenant-id is rejected', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/kubernetes/clusters' });
  expect(res.statusCode).toBe(400);
  await server.close();
});
