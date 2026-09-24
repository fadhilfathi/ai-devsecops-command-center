import { describe, expect, it } from 'vitest';
import { buildAssetRepository } from './repositories/asset.repository.js';
import { buildScanRepository } from './repositories/scan.repository.js';
import { buildFindingRepository } from './repositories/finding.repository.js';
import { seedDemoData } from './seed.js';

const TENANT = '00000000-0000-4000-8000-000000000000';

describe('seedDemoData', () => {
  it('is idempotent — seeding twice does not duplicate rows', async () => {
    const assets = buildAssetRepository();
    const scans = buildScanRepository();
    const findings = buildFindingRepository();

    await seedDemoData({ assets, scans, findings }, TENANT);
    const first = await assets.list(TENANT);
    expect(first.length).toBeGreaterThan(0);

    await seedDemoData({ assets, scans, findings }, TENANT);
    const second = await assets.list(TENANT);
    expect(second.length).toBe(first.length);
  });

  it('leaves the tenant empty when never called', async () => {
    const assets = buildAssetRepository();
    expect(await assets.list(TENANT)).toEqual([]);
  });
});
