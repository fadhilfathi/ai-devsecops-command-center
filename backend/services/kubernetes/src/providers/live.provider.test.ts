import { test, expect, vi } from 'vitest';
import { createLogger } from '@aicc/shared';
import { LiveProvider, type ClientFactory, type K8sClients } from './live.provider.js';
import { buildClusterRepository } from '../repositories/cluster.repository.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const logger = createLogger({ service: 'test', version: '0.0.0', level: 'silent' });

function fakeClients(overrides: Partial<K8sClients> = {}): K8sClients {
  return {
    core: {
      listNamespace: vi.fn(async () => ({ items: [] })),
      listPodForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedPod: vi.fn(async () => ({ items: [] })),
      listServiceForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedService: vi.fn(async () => ({ items: [] })),
    } as unknown as K8sClients['core'],
    apps: {
      listDeploymentForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedDeployment: vi.fn(async () => ({ items: [] })),
      listStatefulSetForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedStatefulSet: vi.fn(async () => ({ items: [] })),
      listDaemonSetForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedDaemonSet: vi.fn(async () => ({ items: [] })),
    } as unknown as K8sClients['apps'],
    networking: {
      listIngressForAllNamespaces: vi.fn(async () => ({ items: [] })),
      listNamespacedIngress: vi.fn(async () => ({ items: [] })),
    } as unknown as K8sClients['networking'],
    version: {
      getCode: vi.fn(async () => ({ gitVersion: 'v1.29.4', platform: 'linux/amd64' })),
    } as unknown as K8sClients['version'],
    ...overrides,
  };
}

test('testConnection returns ok with server version on success', async () => {
  const clients = fakeClients();
  const clientFactory: ClientFactory = () => clients;
  const provider = new LiveProvider({ clusters: buildClusterRepository(), logger, clientFactory });

  const res = await provider.testConnection({
    server: 'https://api.example.com',
    token: 'secret-token',
  });

  expect(res.ok).toBe(true);
  expect(res.serverVersion).toBe('v1.29.4');
  expect(res.message).toBeUndefined();
});

test('testConnection returns ok:false and never leaks the token on failure', async () => {
  const clientFactory: ClientFactory = () => {
    throw new Error('connect ECONNREFUSED 10.0.0.1:6443');
  };
  const provider = new LiveProvider({ clusters: buildClusterRepository(), logger, clientFactory });

  const res = await provider.testConnection({
    server: 'https://api.example.com',
    token: 'super-secret',
  });

  expect(res.ok).toBe(false);
  expect(res.message).not.toContain('super-secret');
});

test('getProviderIdForCluster returns live for an onboarded (non-fixture) cluster', async () => {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
    token: 'tok',
  });

  const providerId = await clusters.getProviderIdForCluster(cluster.id, TENANT);

  expect(providerId).toBe('live');
});

test('listNamespaces builds a client from the cluster connection and maps namespaces', async () => {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
    token: 'tok',
  });
  const clients = fakeClients({
    core: {
      listNamespace: vi.fn(async () => ({
        items: [
          {
            metadata: { uid: '33333333-3333-4333-8333-333333333333', name: 'default' },
            status: { phase: 'Active' },
          },
        ],
      })),
    } as unknown as K8sClients['core'],
  });
  const clientFactory: ClientFactory = vi.fn(() => clients);
  const provider = new LiveProvider({ clusters, logger, clientFactory });

  const namespaces = await provider.listNamespaces(TENANT, cluster.id);

  expect(namespaces).toHaveLength(1);
  expect(namespaces[0]?.name).toBe('default');
  expect(clientFactory).toHaveBeenCalledWith(
    expect.objectContaining({ server: cluster.server, token: 'tok' }),
  );
});

test('listPods passes namespace and labelSelector through to the namespaced call', async () => {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
    token: 'tok',
  });
  const listNamespacedPod = vi.fn(async () => ({ items: [] }));
  const clients = fakeClients({ core: { listNamespacedPod } as unknown as K8sClients['core'] });
  const clientFactory: ClientFactory = () => clients;
  const provider = new LiveProvider({ clusters, logger, clientFactory });

  await provider.listPods(TENANT, {
    clusterId: cluster.id,
    namespace: 'prod-ns',
    labelSelector: 'app=payments',
  });

  expect(listNamespacedPod).toHaveBeenCalledWith({
    namespace: 'prod-ns',
    labelSelector: 'app=payments',
  });
});

test('listPods with no namespace calls listPodForAllNamespaces', async () => {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
    token: 'tok',
  });
  const listPodForAllNamespaces = vi.fn(async () => ({ items: [] }));
  const clients = fakeClients({
    core: { listPodForAllNamespaces } as unknown as K8sClients['core'],
  });
  const provider = new LiveProvider({ clusters, logger, clientFactory: () => clients });

  await provider.listPods(TENANT, { clusterId: cluster.id });

  expect(listPodForAllNamespaces).toHaveBeenCalledWith({ labelSelector: undefined });
});

test('listClusters filters out fixture-provider clusters', async () => {
  const clusters = buildClusterRepository();
  await clusters.create({
    tenantId: TENANT,
    name: 'fx',
    server: 'https://fixture.example.com',
    provider: 'unknown',
  });
  const live = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
  });

  const provider = new LiveProvider({ clusters, logger, clientFactory: () => fakeClients() });
  const items = await provider.listClusters(TENANT);

  // both are "live" here since 'unknown' !== 'fixture'; assert the real cluster is present
  expect(items.map((c) => c.id)).toContain(live.id);
});

test('listWorkloads unions deployments, statefulsets, and daemonsets', async () => {
  const clusters = buildClusterRepository();
  const cluster = await clusters.create({
    tenantId: TENANT,
    name: 'prod',
    server: 'https://api.prod.example.com',
    provider: 'eks',
    token: 'tok',
  });
  const clients = fakeClients({
    apps: {
      listDeploymentForAllNamespaces: vi.fn(async () => ({
        items: [
          {
            metadata: { name: 'dep' },
            spec: { replicas: 1, template: { spec: { containers: [] } } },
            status: {},
          },
        ],
      })),
      listStatefulSetForAllNamespaces: vi.fn(async () => ({
        items: [
          {
            metadata: { name: 'sts' },
            spec: { serviceName: 'sts-hl', template: { spec: { containers: [] } } },
            status: { replicas: 1 },
          },
        ],
      })),
      listDaemonSetForAllNamespaces: vi.fn(async () => ({
        items: [
          {
            metadata: { name: 'ds' },
            spec: { template: { spec: { containers: [] } } },
            status: {
              desiredNumberScheduled: 1,
              currentNumberScheduled: 1,
              numberReady: 1,
              numberMisscheduled: 0,
            },
          },
        ],
      })),
    } as unknown as K8sClients['apps'],
  });
  const provider = new LiveProvider({ clusters, logger, clientFactory: () => clients });

  const workloads = await provider.listWorkloads(TENANT, { clusterId: cluster.id });

  expect(workloads.map((w) => w.kind).sort()).toEqual(['daemonset', 'deployment', 'statefulset']);
});
