import { describe, expect, it } from 'vitest';
import { buildFrameworkRepository } from './framework.repository.js';

describe('framework repository', () => {
  const repo = buildFrameworkRepository();

  it('serves the same catalogue to every tenant — it holds no per-tenant state', async () => {
    const listA = await repo.list('11111111-1111-1111-1111-111111111111');
    const listB = await repo.list('22222222-2222-2222-2222-222222222222');
    expect(listA).toEqual(listB);
    expect(listA).toEqual(repo.supported());
  });

  it('returns the catalogue unchanged across repeated reads', async () => {
    const tenant = '11111111-1111-1111-1111-111111111111';
    expect(await repo.list(tenant)).toEqual(await repo.list(tenant));
  });

  it('exposes the four documented frameworks with complete metadata', () => {
    const supported = repo.supported();
    expect(supported.map((f) => f.id)).toEqual(['cis_v8', 'nist_800_53', 'soc2', 'iso_27001']);
    for (const framework of supported) {
      expect(framework.name).not.toBe('');
      expect(framework.version).not.toBe('');
      expect(framework.description).not.toBe('');
      expect(framework.controlCount).toBeGreaterThan(0);
    }
  });
});
