import { test, expect } from 'vitest';
import Fastify from 'fastify';
import { createLogger, InMemoryEventBus } from '@aicc/shared';
import { buildKubernetesRoutes } from './kubernetes.js';
import { buildProviderRegistry } from '../providers/registry.js';
import { buildClusterRepository } from '../repositories/cluster.repository.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const logger = createLogger({ service: 'test', version: '0.0.0', level: 'silent' });

async function buildTestServer() {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'fixture-cluster',
    server: 'https://fixture.example.com',
    provider: 'eks',
  });
  const providers = buildProviderRegistry({ logger, clusters });
  const server = Fastify();
  server.decorateRequest('tenantId', '');
  server.decorateRequest('userId', '');
  server.addHook('onRequest', async (req) => {
    req.tenantId = (req.headers['x-tenant-id'] as string) ?? '';
    req.userId = '';
  });
  await server.register(buildKubernetesRoutes, {
    logger,
    clusters,
    providers,
    bus: new InMemoryEventBus(),
  });
  return { server, cluster };
}

test('GET /v1/kubernetes/network-policies returns fixture policies for a tenant cluster', async () => {
  const { server, cluster } = await buildTestServer();

  const res = await server.inject({
    method: 'GET',
    url: `/v1/kubernetes/network-policies?clusterId=${cluster.id}&provider=fixture`,
    headers: { 'x-tenant-id': TENANT },
  });

  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(body.total).toBe(body.items.length);
  expect(body.items.length).toBeGreaterThan(0);
  expect(body.items[0]).toMatchObject({ namespace: expect.any(String), name: expect.any(String) });
  await server.close();
});
