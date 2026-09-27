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

describe('api.downloadSbom (S9-2)', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  // Node's global `URL` has no `createObjectURL`/`revokeObjectURL` (that's a
  // browser-only Blob URL API) — add them as plain stubs rather than
  // replacing the whole `URL` global, which would break `new URL(...)`
  // elsewhere.
  function stubDom() {
    const anchor = { href: '', download: '', click: vi.fn(), remove: vi.fn() };
    const createElement = vi.fn(() => anchor);
    vi.stubGlobal('document', { createElement, body: { appendChild: vi.fn() } });
    const createObjectURL = vi.fn(() => 'blob:mock-url');
    const revokeObjectURL = vi.fn();
    (URL as unknown as { createObjectURL: typeof createObjectURL }).createObjectURL =
      createObjectURL;
    (URL as unknown as { revokeObjectURL: typeof revokeObjectURL }).revokeObjectURL =
      revokeObjectURL;
    return { anchor, createObjectURL, revokeObjectURL };
  }

  it('downloads the mock document without calling fetch when mocks are on', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'true');
    const { anchor } = stubDom();
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    await api.downloadSbom('sbom-1');

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(anchor.click).toHaveBeenCalledTimes(1);
  });

  it('fetches the real export with the tenant header and downloads the filename from Content-Disposition', async () => {
    vi.useFakeTimers();
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    vi.stubEnv('VITE_TENANT_ID', 'acme-tenant');
    const { anchor, createObjectURL, revokeObjectURL } = stubDom();
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'attachment; filename="sbom-1.cdx.json"' },
      blob: async () => new Blob(['{}'], { type: 'application/json' }),
    });
    vi.stubGlobal('fetch', fetchSpy);
    const { api } = await import('./api');

    await api.downloadSbom('sbom-1');

    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/sboms/sbom-1/export?format=cyclonedx-1.5',
      expect.objectContaining({
        headers: expect.objectContaining({ 'x-tenant-id': 'acme-tenant' }),
      }),
    );
    expect(anchor.download).toBe('sbom-1.cdx.json');
    expect(anchor.click).toHaveBeenCalledTimes(1);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    // Revoke is deferred a tick past the click so the browser has started
    // reading the blob URL.
    expect(revokeObjectURL).not.toHaveBeenCalled();
    vi.runAllTimers();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
    vi.useRealTimers();
  });

  it('throws a typed error on 501 without falling back to the mock download', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const { anchor } = stubDom();
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: false,
      status: 501,
      headers: { get: () => null },
      json: async () => ({ message: 'stored as spdx' }),
    });
    vi.stubGlobal('fetch', fetchSpy);
    const { api, SbomExportUnsupportedError } = await import('./api');

    await expect(api.downloadSbom('sbom-1')).rejects.toBeInstanceOf(SbomExportUnsupportedError);
    expect(anchor.click).not.toHaveBeenCalled();
  });

  it('throws a typed error and marks the API degraded on a network failure, without downloading mock content', async () => {
    vi.stubEnv('VITE_USE_MOCKS', 'false');
    const { anchor } = stubDom();
    const fetchSpy = vi.fn().mockRejectedValue(new Error('network down'));
    vi.stubGlobal('fetch', fetchSpy);
    const { api, apiHealth, SbomExportError } = await import('./api');

    await expect(api.downloadSbom('sbom-1')).rejects.toBeInstanceOf(SbomExportError);

    expect(anchor.click).not.toHaveBeenCalled();
    expect(apiHealth.get().degraded).toBe(true);
  });
});

describe('safeDownloadFilename (S9-2)', () => {
  const fallback = 'sbom-1.cyclonedx.json';

  it.each([
    ['quoted', 'attachment; filename="sbom-1.cdx.json"', 'sbom-1.cdx.json'],
    ['unquoted', 'attachment; filename=sbom-1.cdx.json', 'sbom-1.cdx.json'],
    [
      "RFC 5987 filename*=UTF-8''",
      "attachment; filename*=UTF-8''sbom%20report.json",
      'sbom_report.json',
    ],
    ['path traversal', 'attachment; filename="../../etc/passwd"', 'passwd'],
    ['windows separator', 'attachment; filename="a\\b.json"', 'b.json'],
    ['control chars', 'attachment; filename="a\u0000b.json"', 'ab.json'],
    ['no header', '', fallback],
    ['empty filename', 'attachment; filename=""', fallback],
    ['overlong', `attachment; filename="${'a'.repeat(150)}.json"`, 'a'.repeat(100)],
  ])('%s -> %s', async (_label, header, expected) => {
    const { safeDownloadFilename } = await import('./api');
    expect(safeDownloadFilename(header, fallback)).toBe(expected);
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
