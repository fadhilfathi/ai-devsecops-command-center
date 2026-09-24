/**
 * S8-1 — optional demo seed data (`AICC_DEMO_SEED=true`). Idempotent: skips
 * if the demo tenant already has assets.
 */
import type { AssetRepository } from './repositories/asset.repository.js';
import type { ScanRepository } from './repositories/scan.repository.js';
import type { FindingRepository } from './repositories/finding.repository.js';

export async function seedDemoData(
  repos: { assets: AssetRepository; scans: ScanRepository; findings: FindingRepository },
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

  void web;
}
