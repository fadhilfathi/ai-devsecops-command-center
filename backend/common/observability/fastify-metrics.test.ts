import Fastify from 'fastify';
import { Registry } from 'prom-client';
import { test, expect } from 'vitest';

import { registerHttpMetrics } from './fastify-metrics.js';

test('registerHttpMetrics exposes /metrics with the matched route (no raw path params)', async () => {
  const registry = new Registry();
  const server = Fastify();
  registerHttpMetrics(server, { registry });
  server.get('/foo/:id', async () => ({ ok: true }));

  await server.inject({ method: 'GET', url: '/foo/123' });

  const res = await server.inject({ method: 'GET', url: '/metrics' });
  expect(res.statusCode).toBe(200);
  expect(res.body).toContain('http_requests_total');
  expect(res.body).toMatch(/route="\/foo\/:id"/);
  expect(res.body).not.toContain('/foo/123');

  await server.close();
});

test('registerHttpMetrics can run more than once against the same registry', async () => {
  const registry = new Registry();
  const serverA = Fastify();
  const serverB = Fastify();
  registerHttpMetrics(serverA, { registry, exposeRoute: false });
  expect(() => registerHttpMetrics(serverB, { registry, exposeRoute: false })).not.toThrow();
  await serverA.close();
  await serverB.close();
});
