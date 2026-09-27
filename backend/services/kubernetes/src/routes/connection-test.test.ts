import { test, expect, vi } from 'vitest';
import Fastify from 'fastify';
import { createLogger } from '@aicc/shared';
import { buildConnectionTestRoutes } from './connection-test.js';
import { buildClusterRepository } from '../repositories/cluster.repository.js';
import { LiveProvider, type ClientFactory } from '../providers/live.provider.js';
import type { ProviderRegistry } from '../providers/registry.js';
import type { HostnameResolver } from '../ssrf-guard.js';

const logger = createLogger({ service: 'test', version: '0.0.0', level: 'silent' });
// Keeps tests off the real network; individual tests override for the
// hostname-DNS-SSRF cases.
const PUBLIC_RESOLVER: HostnameResolver = async () => [{ address: '203.0.113.10' }];

function fakeVersionClients() {
  return {
    core: {},
    apps: {},
    networking: {},
    version: {
      getCode: vi.fn(async () => ({ gitVersion: 'v1.29.4', platform: 'linux/amd64' })),
    },
  } as unknown as ReturnType<ClientFactory>;
}

async function buildTestServer(
  opts: { clientFactory?: ReturnType<typeof vi.fn>; resolveHostname?: HostnameResolver } = {},
) {
  const clusters = buildClusterRepository();
  const clientFactory = opts.clientFactory ?? vi.fn(() => fakeVersionClients());
  const resolveHostname = opts.resolveHostname ?? PUBLIC_RESOLVER;
  const liveProvider = new LiveProvider({
    clusters,
    logger,
    clientFactory: clientFactory as unknown as ClientFactory,
    resolveHostname,
  });
  const providers: ProviderRegistry = {
    list() {
      return [liveProvider];
    },
    get(id) {
      return id === 'live' ? liveProvider : undefined;
    },
    defaultId() {
      return 'live';
    },
    evictLive() {},
  };
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
  await server.register(buildConnectionTestRoutes, {
    logger,
    clusters,
    providers,
    resolveHostname,
  });
  return { server, clientFactory };
}

test('POST /v1/kubernetes/test-connection rejects a non-admin role with 403, provider never called', async () => {
  const { server, clientFactory } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'viewer' },
    payload: { server: 'https://api.example.com', token: 'tok' },
  });

  expect(res.statusCode).toBe(403);
  expect(clientFactory).not.toHaveBeenCalled();
  await server.close();
});

test('POST /v1/kubernetes/test-connection rejects an unauthenticated caller with 401', async () => {
  const { server, clientFactory } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    payload: { server: 'https://api.example.com', token: 'tok' },
  });

  expect(res.statusCode).toBe(401);
  expect(clientFactory).not.toHaveBeenCalled();
  await server.close();
});

test('POST /v1/kubernetes/test-connection rejects a metadata server URL with 400, client factory never called', async () => {
  const { server, clientFactory } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'platform_admin' },
    payload: { server: 'https://169.254.169.254', token: 'tok' },
  });

  expect(res.statusCode).toBe(400);
  expect(clientFactory).not.toHaveBeenCalled();
  await server.close();
});

test('POST /v1/kubernetes/test-connection rejects a loopback server URL with 400, client factory never called', async () => {
  const { server, clientFactory } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'platform_admin' },
    payload: { server: 'https://127.0.0.1', token: 'tok' },
  });

  expect(res.statusCode).toBe(400);
  expect(clientFactory).not.toHaveBeenCalled();
  await server.close();
});

test('POST /v1/kubernetes/test-connection rejects a hostname resolving to a metadata address, client factory never called', async () => {
  const { server, clientFactory } = await buildTestServer({
    resolveHostname: async () => [{ address: '169.254.169.254' }],
  });

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'platform_admin' },
    payload: { server: 'https://metadata.attacker.example', token: 'tok' },
  });

  expect(res.statusCode).toBe(400);
  expect(clientFactory).not.toHaveBeenCalled();
  await server.close();
});

test('POST /v1/kubernetes/test-connection allows an admin against a safe server', async () => {
  const { server } = await buildTestServer();

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'platform_admin' },
    payload: { server: 'https://api.example.com', token: 'tok' },
  });

  expect(res.statusCode).toBe(200);
  expect(res.json().ok).toBe(true);
});

test('POST /v1/kubernetes/test-connection never echoes the provider error text back to the caller', async () => {
  const failingFactory = vi.fn(() => {
    throw new Error('connect ECONNREFUSED 10.1.2.3:6443 super-secret-upstream-detail');
  });
  const { server } = await buildTestServer({ clientFactory: failingFactory });

  const res = await server.inject({
    method: 'POST',
    url: '/v1/kubernetes/test-connection',
    headers: { 'x-user-role': 'platform_admin' },
    payload: { server: 'https://api.example.com', token: 'tok' },
  });

  expect(res.statusCode).toBe(400);
  expect(JSON.stringify(res.json())).not.toContain('super-secret-upstream-detail');
});
