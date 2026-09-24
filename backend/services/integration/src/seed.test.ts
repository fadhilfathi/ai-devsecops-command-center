import { describe, expect, it } from 'vitest';
import { buildIntegrationRepository } from './repositories/integration.repository.js';
import { seedDemoData } from './seed.js';

const TENANT = '00000000-0000-4000-8000-000000000000';

describe('seedDemoData', () => {
  it('is idempotent — seeding twice does not duplicate rows', async () => {
    const integrations = buildIntegrationRepository();

    await seedDemoData({ integrations }, TENANT);
    const first = await integrations.list(TENANT);
    expect(first.length).toBeGreaterThan(0);

    await seedDemoData({ integrations }, TENANT);
    const second = await integrations.list(TENANT);
    expect(second.length).toBe(first.length);
  });

  it('leaves the tenant empty when never called', async () => {
    const integrations = buildIntegrationRepository();
    expect(await integrations.list(TENANT)).toEqual([]);
  });
});
