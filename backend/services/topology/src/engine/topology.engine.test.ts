import { test, expect } from 'vitest';
import type { Pod, Namespace, NetworkPolicy } from '@aicc/models';
import { inferNetworkPolicy } from './topology.engine.js';
import type { TopologyNode, TopologyEdge } from './topology.engine.js';

const CLUSTER = 'cluster-1';

function makeNode(overrides: Partial<TopologyNode>): TopologyNode {
  return {
    id: overrides.id ?? 'node',
    label: overrides.label ?? 'node',
    kind: 'workload',
    namespace: 'ns-a',
    clusterId: CLUSTER,
    clusterName: 'cluster',
    riskScore: 0,
    tags: [],
    metadata: {},
    ...overrides,
  };
}

function makeEdge(overrides: Partial<TopologyEdge>): TopologyEdge {
  return {
    id: overrides.id ?? 'edge',
    source: 'source',
    target: 'target',
    kind: 'calls',
    weight: 1,
    metadata: {},
    ...overrides,
  };
}

function makePod(overrides: Partial<Pod>): Pod {
  return {
    id: overrides.id ?? 'pod',
    tenantId: 't1',
    clusterId: CLUSTER,
    clusterName: 'cluster',
    namespace: overrides.namespace ?? 'ns-a',
    name: overrides.name ?? 'pod',
    phase: 'running',
    ownerKind: 'Deployment',
    ownerName: overrides.ownerName,
    containers: [],
    conditions: [],
    restarts: 0,
    lastTerminationReason: 'unknown',
    labels: overrides.labels ?? {},
    annotations: {},
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as Pod;
}

function makeNamespace(overrides: Partial<Namespace>): Namespace {
  return {
    id: overrides.id ?? 'ns',
    tenantId: 't1',
    clusterId: CLUSTER,
    clusterName: 'cluster',
    name: overrides.name ?? 'ns-a',
    phase: 'active',
    workloadCount: 0,
    podCount: 0,
    runningPods: 0,
    pendingPods: 0,
    failedPods: 0,
    serviceCount: 0,
    restartsLast1h: 0,
    labels: overrides.labels ?? {},
    annotations: {},
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as Namespace;
}

function makePolicy(overrides: Partial<NetworkPolicy>): NetworkPolicy {
  return {
    id: overrides.id ?? 'policy',
    tenantId: 't1',
    clusterId: CLUSTER,
    namespace: overrides.namespace ?? 'ns-a',
    name: overrides.name ?? 'policy',
    podSelector: overrides.podSelector ?? {},
    policyTypes: overrides.policyTypes ?? ['Ingress'],
    ingress: overrides.ingress ?? [],
    egress: [],
    labels: {},
    createdAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as NetworkPolicy;
}

const target = makeNode({ id: 'target', label: 'target-workload', namespace: 'ns-a' });
const source = makeNode({ id: 'source', label: 'source-workload', namespace: 'ns-a' });
const edge = makeEdge({ source: 'source', target: 'target' });

test('no policy selecting the target -> unrestricted', () => {
  const result = inferNetworkPolicy({
    nodes: [source, target],
    edges: [edge],
    pods: [],
    namespaces: [],
    policies: [],
  });
  expect(result.edges[0]?.metadata.networkPolicy).toBe('unrestricted');
  expect(result.summary.unrestrictedEdges).toBe(1);
});

test('default-deny policy (no ingress rules) -> denied', () => {
  const policy = makePolicy({ podSelector: {}, ingress: [] });
  const result = inferNetworkPolicy({
    nodes: [source, target],
    edges: [edge],
    pods: [],
    namespaces: [],
    policies: [policy],
  });
  expect(result.edges[0]?.metadata.networkPolicy).toBe('denied');
  expect(result.summary.deniedEdges).toBe(1);
});

test('policy with an empty `from` (allow-all) rule -> allowed', () => {
  const policy = makePolicy({ podSelector: {}, ingress: [{ from: [], ports: [] }] });
  const result = inferNetworkPolicy({
    nodes: [source, target],
    edges: [edge],
    pods: [],
    namespaces: [],
    policies: [policy],
  });
  expect(result.edges[0]?.metadata.networkPolicy).toBe('allowed');
  expect(result.summary.allowedEdges).toBe(1);
});

test('namespaceSelector rule matching the source namespace label -> allowed', () => {
  const crossSource = makeNode({ id: 'source', label: 'source-workload', namespace: 'ns-b' });
  const namespaces = [makeNamespace({ name: 'ns-b', labels: { team: 'platform' } })];
  const policy = makePolicy({
    podSelector: {},
    ingress: [{ from: [{ namespaceSelector: { team: 'platform' } }], ports: [] }],
  });
  const result = inferNetworkPolicy({
    nodes: [crossSource, target],
    edges: [edge],
    pods: [],
    namespaces,
    policies: [policy],
  });
  expect(result.edges[0]?.metadata.networkPolicy).toBe('allowed');
});

test('podSelector rule from a different namespace -> denied (podSelector never crosses namespaces)', () => {
  const crossSource = makeNode({ id: 'source', label: 'source-workload', namespace: 'ns-b' });
  const policy = makePolicy({
    podSelector: {},
    ingress: [{ from: [{ podSelector: { app: 'source-workload' } }], ports: [] }],
  });
  const pods = [
    makePod({
      id: 'p1',
      namespace: 'ns-b',
      ownerName: 'source-workload',
      labels: { app: 'source-workload' },
    }),
  ];
  const result = inferNetworkPolicy({
    nodes: [crossSource, target],
    edges: [edge],
    pods,
    namespaces: [],
    policies: [policy],
  });
  expect(result.edges[0]?.metadata.networkPolicy).toBe('denied');
  expect(result.summary.deniedEdges).toBe(1);
});

test('podSelector + namespaceSelector on one peer are ANDed', () => {
  const crossSource = makeNode({ id: 'source', label: 'source-workload', namespace: 'ns-b' });
  const namespaces = [makeNamespace({ name: 'ns-b', labels: { team: 'platform' } })];
  const pods = [
    makePod({
      id: 'p1',
      namespace: 'ns-b',
      ownerName: 'source-workload',
      labels: { app: 'api' },
    }),
  ];
  const peer = { namespaceSelector: { team: 'platform' }, podSelector: { app: 'api' } };
  const matching = makePolicy({ podSelector: {}, ingress: [{ from: [peer], ports: [] }] });
  const wrongPod = makePolicy({
    podSelector: {},
    ingress: [{ from: [{ ...peer, podSelector: { app: 'other' } }], ports: [] }],
  });
  const base = { nodes: [crossSource, target], edges: [edge], pods, namespaces };
  expect(
    inferNetworkPolicy({ ...base, policies: [matching] }).edges[0]?.metadata.networkPolicy,
  ).toBe('allowed');
  expect(
    inferNetworkPolicy({ ...base, policies: [wrongPod] }).edges[0]?.metadata.networkPolicy,
  ).toBe('denied');
});
