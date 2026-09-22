import { test, expect } from 'vitest';
import { buildServer } from './index.js';

// auth-service requires JWT_SECRET with no default; set it before buildServer runs.
process.env.JWT_SECRET = 'test-secret-at-least-16-chars-long';

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
