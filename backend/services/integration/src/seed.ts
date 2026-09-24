/**
 * S8-1 — optional demo seed data (`AICC_DEMO_SEED=true`). Idempotent: skips
 * if the demo tenant already has integrations.
 */
import type { IntegrationRepository } from './repositories/integration.repository.js';

export async function seedDemoData(
  repos: { integrations: IntegrationRepository },
  tenantId: string,
): Promise<void> {
  const existing = await repos.integrations.list(tenantId);
  if (existing.length > 0) return;

  await repos.integrations.create({
    tenantId,
    provider: 'github',
    name: 'GitHub — org repos',
    enabled: true,
  });
  await repos.integrations.create({
    tenantId,
    provider: 'slack',
    name: 'Slack — #security-alerts',
    enabled: true,
  });
}
