/**
 * S8-1 — optional demo seed data (`AICC_DEMO_SEED=true`). Idempotent: skips
 * if the demo tenant already has assets.
 */
import type { AssetRepository } from './repositories/asset.repository.js';
import type { ScanRepository } from './repositories/scan.repository.js';
import type { FindingRepository } from './repositories/finding.repository.js';
import type { SbomRepository } from './repositories/sbom.repository.js';

export async function seedDemoData(
  repos: {
    assets: AssetRepository;
    scans: ScanRepository;
    findings: FindingRepository;
    sboms?: SbomRepository;
  },
  tenantId: string,
): Promise<void> {
  const existing = await repos.assets.list(tenantId);
  if (existing.length > 0) return;

  const owner = '00000000-0000-4000-8000-000000000001';
  const api = await repos.assets.create({
    type: 'service',
    name: 'auth-service',
    ownerId: owner,
    tenantId,
    tags: ['demo'],
  });
  const web = await repos.assets.create({
    type: 'service',
    name: 'frontend',
    ownerId: owner,
    tenantId,
    tags: ['demo'],
  });

  const scan = await repos.scans.create({ assetId: api.id, tenantId, scanner: 'trivy' });

  await repos.findings.create({
    scanId: scan.id,
    tenantId,
    cveId: 'CVE-2024-12345',
    packageName: 'lodash',
    packageVersion: '4.17.20',
    severity: 'high',
    title: 'Prototype pollution in lodash',
    description: 'Demo finding seeded for local/demo environments.',
    remediation: 'Upgrade to lodash >= 4.17.21',
  });
  await repos.findings.create({
    scanId: scan.id,
    tenantId,
    cveId: 'CVE-2023-6789',
    packageName: 'express',
    packageVersion: '4.18.1',
    severity: 'medium',
    title: 'ReDoS in express',
    description: 'Demo finding seeded for local/demo environments.',
  });

  // S8-4 — a minimal CycloneDX-shaped SBOM so the components/graph/heatmap
  // endpoints have something non-empty to join against the findings above.
  // `chalk` carries no finding — it exercises the "no known vulnerabilities"
  // path in the SBOM viewer and dependency graph.
  await repos.sboms?.create({
    tenantId,
    assetId: api.id,
    format: 'cyclonedx',
    document: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: { type: 'application', 'bom-ref': 'root', name: 'auth-service' },
      },
      components: [
        {
          type: 'library',
          'bom-ref': 'lodash@4.17.20',
          name: 'lodash',
          version: '4.17.20',
          purl: 'pkg:npm/lodash@4.17.20',
          licenses: ['MIT'],
        },
        {
          type: 'library',
          'bom-ref': 'express@4.18.1',
          name: 'express',
          version: '4.18.1',
          purl: 'pkg:npm/express@4.18.1',
          licenses: ['MIT'],
        },
        {
          type: 'library',
          'bom-ref': 'chalk@5.3.0',
          name: 'chalk',
          version: '5.3.0',
          purl: 'pkg:npm/chalk@5.3.0',
          licenses: ['MIT'],
        },
      ],
      dependencies: [
        { ref: 'root', dependsOn: ['lodash@4.17.20', 'express@4.18.1'] },
        { ref: 'express@4.18.1', dependsOn: ['chalk@5.3.0'] },
      ],
    },
  });

  void web;
}
