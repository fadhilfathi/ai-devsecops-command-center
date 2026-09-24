/**
 * `GET /v1/vulnerabilities` — S8-4. Browser-facing vulnerability list,
 * derived from findings + a scan->asset join. Distinct from
 * `/v1/findings` (the Sprint-1 internal shape); this route returns the
 * `Vulnerability` wire shape the frontend's Vulnerabilities page expects.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { Logger, UUID } from '@aicc/shared';
import type { FindingRepository } from '../repositories/finding.repository.js';
import type { ScanRepository } from '../repositories/scan.repository.js';
import { toWireVulnerabilities } from '../services/security-analytics.js';

interface Deps {
  logger: Logger;
  findings: FindingRepository;
  scans: ScanRepository;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

const ListQuerySchema = z.object({
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  status: z.enum(['open', 'triaging', 'in_progress', 'resolved', 'suppressed']).optional(),
});

export const buildVulnerabilityRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, findings, scans } = opts;

  server.get('/v1/vulnerabilities', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const [matchedFindings, tenantScans] = await Promise.all([
      findings.list(tenantId, q),
      scans.list(tenantId),
    ]);
    const items = toWireVulnerabilities(matchedFindings, tenantScans);
    return { items, total: items.length };
  });

  logger.debug('security-service vulnerability routes registered');
};
