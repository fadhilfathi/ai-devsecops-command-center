import { test, expect, vi } from 'vitest';
import { createLogger } from '@aicc/shared';
import type { Pod, Workload } from '@aicc/models';
import { buildPrometheusUtilisationSource, buildSyntheticUtilisationSource } from './source.js';

const logger = createLogger({ service: 'test', version: '0.0.0', level: 'silent' });

function workload(overrides: Partial<Workload> = {}): Workload {
  return {
    id: 'a0000000-0000-4000-8000-000000000001',
    tenantId: 't1',
    clusterId: 'c1',
    clusterName: 'cluster-1',
    namespace: 'default',
    kind: 'deployment',
    name: 'web',
    replicas: { desired: 2, ready: 2, updated: 2, available: 2 },
    health: 'healthy',
    conditions: [],
    labels: {},
    resources: {
      cpuRequestsMillicores: 1000,
      cpuLimitsMillicores: 2000,
      memoryRequestsBytes: 1024 * 1024 * 1024,
      memoryLimitsBytes: 2 * 1024 * 1024 * 1024,
    },
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as Workload;
}

function pod(overrides: Partial<Pod> = {}): Pod {
  return {
    id: 'p0000000-0000-4000-8000-000000000001',
    tenantId: 't1',
    clusterId: 'c1',
    clusterName: 'cluster-1',
    namespace: 'default',
    name: 'web-abc123',
    phase: 'running',
    ownerKind: 'deployment',
    ownerName: 'web',
    containers: [
      {
        name: 'web',
        image: 'web:latest',
        state: 'running',
        ready: true,
        restartCount: 0,
        lastTerminationReason: 'unknown',
        resources: {
          cpuRequestsMillicores: 0,
          cpuLimitsMillicores: 0,
          memoryRequestsBytes: 0,
          memoryLimitsBytes: 0,
        },
        privileged: false,
        runAsRoot: false,
        addedCapabilities: [],
        hostPaths: [],
      },
    ],
    conditions: [],
    restarts: 0,
    lastTerminationReason: 'unknown',
    labels: {},
    annotations: {},
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as Pod;
}

function vectorResponse(values: Record<string, number>): unknown {
  return {
    status: 'success',
    data: {
      resultType: 'vector',
      result: Object.entries(values).map(([podName, v]) => ({
        metric: { pod: podName },
        value: [1234, String(v)],
      })),
    },
  };
}

test('synthetic source returns deterministic defaults', async () => {
  const source = buildSyntheticUtilisationSource();
  const w = workload();
  const { utilisation, kind } = await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-02T00:00:00Z',
  });
  expect(utilisation?.[w.id]).toEqual({ cpuP50: 0.4, cpuP95: 0.6, memoryP50: 0.5, memoryP95: 0.7 });
  expect(kind).toBe('synthetic');
});

test('prometheus source builds correct PromQL and sums across pods', async () => {
  const w = workload({ resources: { ...workload().resources, cpuRequestsMillicores: 1000 } });
  const pods = [pod({ name: 'web-1' }), pod({ name: 'web-2' })];
  const queries: string[] = [];
  const fetchImpl = vi.fn(async (url: string | URL) => {
    const u = new URL(String(url));
    const q = u.searchParams.get('query') ?? '';
    queries.push(q);
    if (q.startsWith('quantile_over_time(0.5, sum by (pod) (rate(')) {
      return new Response(JSON.stringify(vectorResponse({ 'web-1': 0.3, 'web-2': 0.2 })));
    }
    if (q.startsWith('quantile_over_time(0.95, sum by (pod) (rate(')) {
      return new Response(JSON.stringify(vectorResponse({ 'web-1': 0.4, 'web-2': 0.35 })));
    }
    return new Response(JSON.stringify(vectorResponse({})));
  }) as unknown as typeof fetch;

  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl,
    logger,
  });
  const { utilisation, kind } = await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods,
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });

  expect(queries.some((q) => q.includes('namespace="default"'))).toBe(true);
  expect(queries.some((q) => q.includes('pod=~"web-1|web-2"'))).toBe(true);
  expect(queries.some((q) => q.includes('[10m:5m]'))).toBe(true);

  // cpuP95 = (0.4 + 0.35) / (1 core/pod * 2 pods) = 0.375
  expect(utilisation?.[w.id]?.cpuP95).toBeCloseTo(0.375);
  // cpuP50 = (0.3 + 0.2) / (1 core/pod * 2 pods) = 0.25
  expect(utilisation?.[w.id]?.cpuP50).toBeCloseTo(0.25);
  expect(kind).toBe('prometheus');
});

test('falls back to name-prefix regex when no pods are known', async () => {
  const w = workload({ name: 'api' });
  const fetchImpl = vi.fn(async () => new Response(JSON.stringify(vectorResponse({}))));
  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    logger,
  });
  await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });
  const calledUrl = String(fetchImpl.mock.calls[0]?.[0]);
  expect(decodeURIComponent(calledUrl)).toContain('pod=~"^api-.*"');
});

test('missing series leaves workload undefined (engine falls back to defaults)', async () => {
  const w = workload();
  const fetchImpl = vi.fn(async () => new Response(JSON.stringify(vectorResponse({}))));
  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    logger,
  });
  const { utilisation, kind } = await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [pod()],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });
  expect(utilisation?.[w.id]).toBeUndefined();
  expect(kind).toBe('synthetic');
});

test('non-200 response degrades to no utilisation for that workload', async () => {
  const w = workload();
  const fetchImpl = vi.fn(async () => new Response('error', { status: 500 }));
  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    logger,
  });
  const { utilisation, kind } = await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [pod()],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });
  expect(utilisation).toEqual({});
  expect(kind).toBe('synthetic');
});

test('escapes regex metacharacters in workload/pod names', async () => {
  const w = workload({ name: 'a.b+c' });
  const fetchImpl = vi.fn(async () => new Response(JSON.stringify(vectorResponse({}))));
  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    logger,
  });
  await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });
  const calledUrl = String(fetchImpl.mock.calls[0]?.[0]);
  // escapeRegex produces `a\.b\+c`, then promQuote doubles the backslashes
  // so the PromQL string literal round-trips to the correct regex.
  expect(decodeURIComponent(calledUrl)).toContain('pod=~"^a\\\\.b\\\\+c-.*"');
});

test('quotes and escapes label values to prevent PromQL injection', async () => {
  const injected = 'foo"} or vector(1) #';
  const w = workload({ namespace: injected, name: injected });
  const fetchImpl = vi.fn(async () => new Response(JSON.stringify(vectorResponse({}))));
  const source = buildPrometheusUtilisationSource({
    baseUrl: 'http://prometheus:9090',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    logger,
  });
  await source.fetch({
    tenantId: 't1',
    workloads: [w],
    pods: [],
    windowStart: '2026-01-01T00:00:00Z',
    windowEnd: '2026-01-01T00:10:00Z',
  });
  const query = decodeURIComponent(String(fetchImpl.mock.calls[0]?.[0]));

  // The namespace matcher must contain an escaped quote, not a raw one.
  expect(query).toContain('namespace="foo\\"} or vector(1) #"');
  // No unescaped `"` should appear inside either label matcher.
  const namespaceMatcher = query.match(/namespace="((?:[^"\\]|\\.)*)"/);
  const podMatcher = query.match(/pod=~"((?:[^"\\]|\\.)*)"/);
  expect(namespaceMatcher).not.toBeNull();
  expect(podMatcher).not.toBeNull();
  expect(namespaceMatcher![1]).not.toMatch(/(?<!\\)"/);
  expect(podMatcher![1]).not.toMatch(/(?<!\\)"/);
});
