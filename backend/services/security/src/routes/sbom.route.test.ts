import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { signAccessToken, AUTH_DEV_DEFAULT_SECRET } from '@aicc/shared';
import { buildServer } from '../index.js';

const tokenOpts = { secret: AUTH_DEV_DEFAULT_SECRET, issuer: 'aicc', audience: 'aicc-api' };

function authHeaders(tenantId: string, role = 'security_engineer') {
  const token = signAccessToken({ sub: `user-${tenantId}`, role, tenantId }, tokenOpts);
  return { authorization: `Bearer ${token}` };
}

const SBOM_DOC = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { timestamp: '2026-06-01T00:00:00Z', component: { 'bom-ref': 'root' } },
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
};

/** Seed one asset + sbom for `tenantId` via the public API; returns the sbom id. */
async function seedSbom(server: Awaited<ReturnType<typeof buildServer>>, tenantId: string) {
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

  const sbomRes = await server.inject({
    method: 'POST',
    url: '/v1/sboms',
    headers,
    payload: { assetId, format: 'cyclonedx', document: SBOM_DOC },
  });
  const sbomId = sbomRes.json().sbom.id as string;

  return { assetId, sbomId };
}

describe('sbom routes', () => {
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

  describe('GET /v1/sboms/:id/export', () => {
    it('returns the stored document with content-type and a filename in Content-Disposition', async () => {
      const { sbomId } = await seedSbom(server, 'tenant-export-a');
      const res = await server.inject({
        method: 'GET',
        url: `/v1/sboms/${sbomId}/export`,
        headers: authHeaders('tenant-export-a'),
      });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.headers['content-disposition']).toBe(`attachment; filename="${sbomId}.cdx.json"`);
      expect(res.json()).toEqual(SBOM_DOC);
    });

    it('returns 501 when the requested format does not match the stored format', async () => {
      const { sbomId } = await seedSbom(server, 'tenant-export-b');
      const res = await server.inject({
        method: 'GET',
        url: `/v1/sboms/${sbomId}/export?format=spdx-2.3`,
        headers: authHeaders('tenant-export-b'),
      });
      expect(res.statusCode).toBe(501);
      expect(res.json().code).toBe('NOT_IMPLEMENTED');
    });

    it('returns 404 (not 403) when tenant B requests tenant A SBOM id', async () => {
      const { sbomId } = await seedSbom(server, 'tenant-export-owner');
      const res = await server.inject({
        method: 'GET',
        url: `/v1/sboms/${sbomId}/export`,
        headers: authHeaders('tenant-export-other'),
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 with no token', async () => {
      const { sbomId } = await seedSbom(server, 'tenant-export-noauth');
      const res = await server.inject({ method: 'GET', url: `/v1/sboms/${sbomId}/export` });
      expect(res.statusCode).toBe(401);
    });

    it('returns 400 on a malformed id', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/v1/sboms/not-a-uuid/export',
        headers: authHeaders('tenant-export-badid'),
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /v1/sboms/:id', () => {
    it('returns 400 on a malformed id', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/v1/sboms/not-a-uuid',
        headers: authHeaders('tenant-getid-badid'),
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 404 (not 403) when tenant B requests tenant A SBOM id', async () => {
      const { sbomId } = await seedSbom(server, 'tenant-getid-owner');
      const res = await server.inject({
        method: 'GET',
        url: `/v1/sboms/${sbomId}`,
        headers: authHeaders('tenant-getid-other'),
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('GET /v1/sbom/components tenant isolation', () => {
    it('does not leak components across tenants', async () => {
      await seedSbom(server, 'tenant-components-a');

      const res = await server.inject({
        method: 'GET',
        url: '/v1/sbom/components',
        headers: authHeaders('tenant-components-b'),
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().items).toHaveLength(0);
    });

    it('returns the owning tenant its own components', async () => {
      await seedSbom(server, 'tenant-components-c');

      const res = await server.inject({
        method: 'GET',
        url: '/v1/sbom/components',
        headers: authHeaders('tenant-components-c'),
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().items).toHaveLength(1);
      expect(res.json().items[0]).toMatchObject({ name: 'lodash' });
    });
  });
});
