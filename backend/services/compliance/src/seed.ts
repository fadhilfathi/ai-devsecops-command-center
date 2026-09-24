/**
 * S8-1 — optional demo seed data (`AICC_DEMO_SEED=true`). Idempotent: skips
 * if the demo tenant already has controls.
 */
import type { ControlRepository } from './repositories/control.repository.js';

export async function seedDemoData(
  repos: { controls: ControlRepository },
  tenantId: string,
): Promise<void> {
  const existing = await repos.controls.list(tenantId);
  if (existing.length > 0) return;

  await repos.controls.create({
    tenantId,
    framework: 'soc2',
    controlId: 'CC6.1',
    title: 'Logical access controls',
    description: 'Demo control seeded for local/demo environments.',
  });
  await repos.controls.create({
    tenantId,
    framework: 'cis_v8',
    controlId: '4.1',
    title: 'Establish and maintain a secure configuration process',
    description: 'Demo control seeded for local/demo environments.',
  });
  await repos.controls.create({
    tenantId,
    framework: 'nist_800_53',
    controlId: 'AC-2',
    title: 'Account management',
    description: 'Demo control seeded for local/demo environments.',
  });
}
