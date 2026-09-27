import { test, expect } from 'vitest';
import Fastify from 'fastify';
import { createLogger, InMemoryEventBus } from '@aicc/shared';
import { buildKubernetesRoutes } from './kubernetes.js';
import { buildProviderRegistry } from '../providers/registry.js';
import { buildClusterRepository } from '../repositories/cluster.repository.js';
import type { HostnameResolver } from '../ssrf-guard.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const logger = createLogger({ service: 'test', version: '0.0.0', level: 'silent' });
// Keeps tests off the real network; individual tests override for the
// hostname-DNS-SSRF cases.
const PUBLIC_RESOLVER: HostnameResolver = async () => [{ address: '203.0.113.10' }];

async function buildTestServer(resolveHostname: HostnameResolver = PUBLIC_RESOLVER) {
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
  server.decorateRequest('userRole', undefined);
  server.addHook('onRequest', async (req) => {
    req.tenantId = (req.headers['x-tenant-id'] as string) ?? '';
    req.userId = '';
    req.userRole = req.headers['x-user-role'] as never;
  });
  server.setErrorHandler((err, _req, reply) => {
    const statusCode = (err as { statusCode?: number }).statusCode ?? 500;
    reply.code(statusCode).send({ code: (err as { code?: string }).code, message: err.message });
  });
  await server.register(buildKubernetesRoutes, {
    logger,
    clusters,
    providers,
    bus: new InMemoryEventBus(),
    resolveHostname,
  });
  return { server, cluster, clusters };
}

function adminHeaders(extra: Record<string, string> = {}) {
  return { 'x-tenant-id': TENANT, 'x-user-role': 'platform_admin', ...extra };
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

test('POST /v1/kubernetes/clusters creates a cluster; it appears in the list without secrets', async () => {
  const { server } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/clusters',
    headers: adminHeaders(),
    payload: {
      name: 'onboarded',
      provider: 'eks',
      environment: 'prod',
      server: 'https://api.onboarded.example.com',
      token: 'super-secret-token',
      caBundle: 'ca-data',
    },
  });

  expect(res.statusCode).toBe(201);
  const created = res.json();
  expect(created).not.toHaveProperty('token');
  expect(created).not.toHaveProperty('caBundle');
  expect(JSON.stringify(created)).not.toContain('super-secret-token');

  const listRes = await server.inject({
    method: 'GET',
    url: '/v1/kubernetes/clusters',
    headers: { 'x-tenant-id': TENANT },
  });
  const listed = listRes.json().items.find((c: { id: string }) => c.id === created.id);
  expect(listed).toBeDefined();
  expect(JSON.stringify(listed)).not.toContain('super-secret-token');

  await server.close();
});

test('POST /v1/kubernetes/clusters rejects a non-admin role with 403', async () => {
  const { server } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/clusters',
    headers: adminHeaders({ 'x-user-role': 'viewer' }),
    payload: {
      name: 'blocked',
      provider: 'eks',
      server: 'https://api.blocked.example.com',
    },
  });

  expect(res.statusCode).toBe(403);
  await server.close();
});

test('PATCH /v1/kubernetes/clusters/:id rotates credentials and rebuilds the live client', async () => {
  const { server, cluster, clusters } = await buildTestServer();
  await clusters.update(cluster.id, TENANT, { token: 'old-token' });

  const res = await server.inject({
    method: 'PATCH',
    url: `/v1/kubernetes/clusters/${cluster.id}`,
    headers: adminHeaders(),
    payload: { name: 'renamed', token: 'new-token' },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().name).toBe('renamed');
  expect(res.json()).not.toHaveProperty('token');

  const conn = await clusters.getConnection(cluster.id, TENANT);
  expect(conn?.token).toBe('new-token');

  await server.close();
});

test('DELETE /v1/kubernetes/clusters/:id removes the cluster; subsequent access 404s', async () => {
  const { server, cluster } = await buildTestServer();

  const del = await server.inject({
    method: 'DELETE',
    url: `/v1/kubernetes/clusters/${cluster.id}`,
    headers: adminHeaders(),
  });
  expect(del.statusCode).toBe(204);

  const getAfter = await server.inject({
    method: 'GET',
    url: `/v1/kubernetes/namespaces?clusterId=${cluster.id}`,
    headers: { 'x-tenant-id': TENANT },
  });
  expect(getAfter.statusCode).toBe(404);

  await server.close();
});

test('DELETE /v1/kubernetes/clusters/:id from another tenant 404s', async () => {
  const { server, cluster } = await buildTestServer();

  const res = await server.inject({
    method: 'DELETE',
    url: `/v1/kubernetes/clusters/${cluster.id}`,
    headers: adminHeaders({ 'x-tenant-id': TENANT_B }),
  });

  expect(res.statusCode).toBe(404);
  await server.close();
});

test('POST /v1/kubernetes/clusters rejects a link-local server URL (SSRF guard)', async () => {
  const { server } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/clusters',
    headers: adminHeaders(),
    payload: {
      name: 'ssrf-attempt',
      provider: 'eks',
      server: 'https://169.254.169.254',
    },
  });

  expect(res.statusCode).toBe(400);
  await server.close();
});

test('POST /v1/kubernetes/clusters rejects a hostname that resolves to a metadata address (DNS SSRF check)', async () => {
  const { server } = await buildTestServer(async () => [{ address: '169.254.169.254' }]);

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/clusters',
    headers: adminHeaders(),
    payload: {
      name: 'dns-ssrf-attempt',
      provider: 'eks',
      server: 'https://metadata.attacker.example',
    },
  });

  expect(res.statusCode).toBe(400);
  await server.close();
});
