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

test('GET /v1/controls returns the control list', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/controls' });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(Array.isArray(body.items)).toBe(true);
  expect(body.total).toBe(body.items.length);
  await server.close();
});
