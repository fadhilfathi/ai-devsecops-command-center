import { describe, expect, it } from 'vitest';
import { buildControlRepository } from './repositories/control.repository.js';
import { seedDemoData } from './seed.js';

const TENANT = '00000000-0000-4000-8000-000000000000';

describe('seedDemoData', () => {
  it('is idempotent — seeding twice does not duplicate rows', async () => {
    const controls = buildControlRepository();

    await seedDemoData({ controls }, TENANT);
    const first = await controls.list(TENANT);
    expect(first.length).toBeGreaterThan(0);

    await seedDemoData({ controls }, TENANT);
    const second = await controls.list(TENANT);
    expect(second.length).toBe(first.length);
  });

  it('leaves the tenant empty when never called', async () => {
    const controls = buildControlRepository();
    expect(await controls.list(TENANT)).toEqual([]);
  });
});
