import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { signAccessToken, AUTH_DEV_DEFAULT_SECRET } from '@aicc/shared';
import { buildServer } from '../index.js';

const tokenOpts = { secret: AUTH_DEV_DEFAULT_SECRET, issuer: 'aicc', audience: 'aicc-api' };

function authHeaders(tenantId: string, role = 'security_engineer') {
  const token = signAccessToken({ sub: `user-${tenantId}`, role, tenantId }, tokenOpts);
  return { authorization: `Bearer ${token}` };
}

/** Seed one asset + scan + finding + sbom for `tenantId` via the public API. */
async function seedTenant(server: Awaited<ReturnType<typeof buildServer>>, tenantId: string) {
  const headers = authHeaders(tenantId);

  const assetRes = await server.inject({
    method: 'POST',
    url: '/v1/assets',
    headers,
    payload: {
      type: 'service',
      name: 'demo-svc',
      ownerId: '00000000-0000-4000-8000-000000000099',
    },
  });
  const assetId = assetRes.json().asset.id as string;

  const scanRes = await server.inject({
    method: 'POST',
    url: '/v1/scans',
    headers,
    payload: { assetId, scanner: 'trivy' },
  });
  const scanId = scanRes.json().scan.id as string;

  await server.inject({
    method: 'POST',
    url: `/v1/scans/${scanId}/complete`,
    headers,
    payload: {
      findings: [
        {
          cveId: 'CVE-2024-0001',
          packageName: 'lodash',
          packageVersion: '4.17.20',
          severity: 'critical',
          title: 'demo critical finding',
          description: 'seeded for tests',
        },
      ],
    },
  });

  await server.inject({
    method: 'POST',
    url: '/v1/sboms',
    headers,
    payload: {
      assetId,
      format: 'cyclonedx',
      document: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: { timestamp: new Date().toISOString(), component: { 'bom-ref': 'root' } },
        components: [
          {
            type: 'library',
            'bom-ref': 'lodash@4.17.20',
            name: 'lodash',
            version: '4.17.20',
            purl: 'pkg:npm/lodash@4.17.20',
          },
        ],
        dependencies: [{ ref: 'root', dependsOn: ['lodash@4.17.20'] }],
      },
    },
  });

  return { assetId, scanId };
}

describe('S8-4 security analytics routes', () => {
  let prevBypass: string | undefined;
  let server: Awaited<ReturnType<typeof buildServer>>;

  beforeEach(async () => {
    prevBypass = process.env.AUTH_DEV_BYPASS;
    process.env.AUTH_DEV_BYPASS = 'false';
    server = await buildServer();
  });

  afterEach(async () => {
    await server.close();
    if (prevBypass === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prevBypass;
  });

  const ROUTES = [
    '/v1/vulnerabilities',
    '/v1/sbom/components',
    '/security/score',
    '/security/vuln-timeline',
    '/security/risk-heatmap',
    '/security/graph',
  ];

  it.each(ROUTES)('%s requires authentication', async (url) => {
    const res = await server.inject({ method: 'GET', url });
    expect(res.statusCode).toBe(401);
  });

  it('GET /v1/vulnerabilities returns the seeded finding, joined to its asset', async () => {
    const { assetId } = await seedTenant(server, 'tenant-a');
    const res = await server.inject({
      method: 'GET',
      url: '/v1/vulnerabilities',
      headers: authHeaders('tenant-a'),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items).toHaveLength(1);
    expect(body.items[0]).toMatchObject({
      cve: 'CVE-2024-0001',
      severity: 'critical',
      package: 'lodash',
      assetId,
    });
  });

  it('GET /v1/sbom/components returns the seeded component, ecosystem-tagged', async () => {
    await seedTenant(server, 'tenant-b');
    const res = await server.inject({
      method: 'GET',
      url: '/v1/sbom/components',
      headers: authHeaders('tenant-b'),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items).toHaveLength(1);
    expect(body.items[0]).toMatchObject({ name: 'lodash', ecosystem: 'npm', vulnerabilities: 1 });
  });

  it('GET /security/score reflects the seeded critical finding', async () => {
    await seedTenant(server, 'tenant-c');
    const res = await server.inject({
      method: 'GET',
      url: '/security/score',
      headers: authHeaders('tenant-c'),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.composite).toBe(90); // 100 - (1 critical * 10)
    const critical = body.subMetrics.find((m: { id: string }) => m.id === 'critical-vulns');
    expect(critical.value).toBe(1);
  });

  it('GET /security/risk-heatmap buckets the seeded finding under npm/critical', async () => {
    await seedTenant(server, 'tenant-d');
    const res = await server.inject({
      method: 'GET',
      url: '/security/risk-heatmap',
      headers: authHeaders('tenant-d'),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    const cell = body.cells.find(
      (c: { ecosystem: string; severity: string }) =>
        c.ecosystem === 'npm' && c.severity === 'critical',
    );
    expect(cell.count).toBe(1);
    expect(body.totalVulns).toBe(1);
  });

  it('GET /security/graph returns the seeded component as a node', async () => {
    await seedTenant(server, 'tenant-e');
    const res = await server.inject({
      method: 'GET',
      url: '/security/graph',
      headers: authHeaders('tenant-e'),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.nodes).toHaveLength(1);
    expect(body.nodes[0]).toMatchObject({ label: 'lodash', ecosystem: 'npm', vulnCount: 1 });
  });

  it('tenant isolation: tenant B sees none of tenant A data across every new route', async () => {
    await seedTenant(server, 'tenant-a2');
    const headersB = authHeaders('tenant-b2');

    const vulns = await server.inject({
      method: 'GET',
      url: '/v1/vulnerabilities',
      headers: headersB,
    });
    expect(vulns.json().items).toHaveLength(0);

    const components = await server.inject({
      method: 'GET',
      url: '/v1/sbom/components',
      headers: headersB,
    });
    expect(components.json().items).toHaveLength(0);

    const score = await server.inject({ method: 'GET', url: '/security/score', headers: headersB });
    expect(score.json()).toMatchObject({ hasData: false, composite: null, band: null });

    const heatmap = await server.inject({
      method: 'GET',
      url: '/security/risk-heatmap',
      headers: headersB,
    });
    expect(heatmap.json().totalVulns).toBe(0);

    const graph = await server.inject({ method: 'GET', url: '/security/graph', headers: headersB });
    expect(graph.json().nodes).toHaveLength(0);
  });
});
