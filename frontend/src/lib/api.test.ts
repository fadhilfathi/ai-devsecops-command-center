import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockClusters } from './infrastructure.mock';

// `mockClusters` carries a `lastSyncedAt: new Date().toISOString()`, so
// each fresh module import produces a structurally-equal-but-not-identical
// fallback. Compare ids/total instead of deep-equaling the whole object.
function expectIsFallback(result: { items: { id: string }[]; total: number }) {
  expect(result.total).toBe(mockClusters.length);
  expect(result.items.map((c) => c.id)).toEqual(mockClusters.map((c) => c.id));
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe('api get()', () => {
  it('returns the fallback without fetching when mocks are on', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'true');
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    const result = await api.kubernetesClusters();

    expectIsFallback(result);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('calls the right URL with the tenant header when mocks are off', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    vi.stubEnv('VITE_TENANT_ID', 'acme-tenant');
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ items: [], total: 0 }),
    });
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    await api.kubernetesClusters();

    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/clusters',
      expect.objectContaining({
        headers: expect.objectContaining({ 'x-tenant-id': 'acme-tenant' }),
      }),
    );
  });

  it('returns the fallback on a non-2xx response', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 503 });
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    const result = await api.kubernetesClusters();

    expectIsFallback(result);
  });

  it('returns the fallback when fetch throws', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi.fn().mockRejectedValue(new Error('network down'));
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    const result = await api.kubernetesClusters();

    expectIsFallback(result);
  });
});

describe('api URLs — one per service group (S6-1 resource-based proxy table)', () => {
  async function urlFor(call: (api: (typeof import('./api'))['api']) => Promise<unknown>) {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');
    await call(api);
    return fetchSpy.mock.calls[0]?.[0] as string;
  }

  it('kubernetes: /api/clusters', async () => {
    expect(await urlFor((api) => api.kubernetesClusters())).toBe('/api/clusters');
  });

  it('k8s-health: /api/health/clusters', async () => {
    expect(await urlFor((api) => api.healthClusters())).toBe('/api/health/clusters');
  });

  it('cost: /api/cost/analysis', async () => {
    expect(await urlFor((api) => api.costAnalysis())).toBe('/api/cost/analysis');
  });

  it('topology: /api/topology/graphs', async () => {
    expect(await urlFor((api) => api.topologyGraphs())).toBe('/api/topology/graphs');
  });

  it('security/assets: /api/assets', async () => {
    expect(await urlFor((api) => api.assets())).toBe('/api/assets');
  });

  it('incidents: /api/incidents', async () => {
    expect(await urlFor((api) => api.incidents())).toBe('/api/incidents');
  });

  it('compliance/controls: /api/controls', async () => {
    expect(await urlFor((api) => api.compliance())).toBe('/api/controls');
  });

  it('vulnerabilities: /api/vulnerabilities', async () => {
    expect(await urlFor((api) => api.vulnerabilities())).toBe('/api/vulnerabilities');
  });

  it('sbom components: /api/sbom/components', async () => {
    expect(await urlFor((api) => api.sbom())).toBe('/api/sbom/components');
  });

  it('security score: /api/security/score', async () => {
    expect(await urlFor((api) => api.securityScore())).toBe('/api/security/score');
  });

  it('vuln timeline: /api/security/vuln-timeline?range=7d', async () => {
    expect(await urlFor((api) => api.vulnTimeline('7d'))).toBe(
      '/api/security/vuln-timeline?range=7d',
    );
  });

  it('risk heatmap: /api/security/risk-heatmap', async () => {
    expect(await urlFor((api) => api.riskHeatmap())).toBe('/api/security/risk-heatmap');
  });

  it('graph: /api/security/graph?sbomId=sbom-1', async () => {
    expect(await urlFor((api) => api.graphData('sbom-1'))).toBe(
      '/api/security/graph?sbomId=sbom-1',
    );
  });
});

describe('mock-only accessors', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('sbomExportUrl never calls fetch, even when mocks are off', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    api.sbomExportUrl('sbom-1');

    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('apiHealth', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('flips degraded to true after a failed request', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 500 });
    vi.stubGlobal('fetch', fetchSpy);
    const { api, apiHealth } = await import('./api');

    expect(apiHealth.get().degraded).toBe(false);
    await api.assets();
    expect(apiHealth.get().degraded).toBe(true);
    expect(apiHealth.get().failures).toContain('/assets');
  });
});

describe('api auth integration', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('sends the token as a bearer header once logged in, and clears it on a 401', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ accessToken: 'tok-1' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: false, status: 401 });
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');
    const { login, getToken } = await import('./auth');

    await login('admin@aicc.local');
    expect(getToken()).toBe('tok-1');

    await api.assets();
    expect(fetchSpy).toHaveBeenLastCalledWith(
      '/api/assets',
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: 'Bearer tok-1' }),
      }),
    );

    await api.assets();
    expect(getToken()).toBeNull();
  });
});
