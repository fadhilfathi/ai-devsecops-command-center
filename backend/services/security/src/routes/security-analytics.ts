/**
 * S8-4 — security analytics endpoints consumed by the dashboard
 * visualizations (SecurityScore, VulnTimeline, RiskHeatmap, DependencyGraph).
 * All aggregation logic lives in `../services/security-analytics.ts`;
 * these handlers just fetch tenant-scoped repo data and hand it off.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { Logger, UUID } from '@aicc/shared';
import type { AssetRepository } from '../repositories/asset.repository.js';
import type { FindingRepository } from '../repositories/finding.repository.js';
import type { SbomRepository } from '../repositories/sbom.repository.js';
import {
  buildDependencyGraph,
  computeRiskHeatmap,
  computeSecurityScore,
  computeVulnTimeline,
  extractSbomComponents,
} from '../services/security-analytics.js';

interface Deps {
  logger: Logger;
  assets: AssetRepository;
  findings: FindingRepository;
  sboms: SbomRepository;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

const TimelineQuerySchema = z.object({
  range: z.enum(['7d', '30d', '90d', '1y']).default('30d'),
});

const GraphQuerySchema = z.object({
  sbomId: z.string().optional(),
});

export const buildSecurityAnalyticsRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, assets, findings, sboms } = opts;

  server.get('/security/score', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const [tenantFindings, tenantAssets, tenantSboms] = await Promise.all([
      findings.list(tenantId),
      assets.list(tenantId),
      sboms.list(tenantId),
    ]);
    return computeSecurityScore(tenantFindings, tenantAssets, tenantSboms);
  });

  server.get('/security/vuln-timeline', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = TimelineQuerySchema.parse(req.query ?? {});
    const tenantFindings = await findings.list(tenantId);
    return computeVulnTimeline(tenantFindings, q.range);
  });

  server.get('/security/risk-heatmap', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const [tenantFindings, tenantSboms] = await Promise.all([
      findings.list(tenantId),
      sboms.list(tenantId),
    ]);
    const components = extractSbomComponents(tenantSboms, tenantFindings);
    return computeRiskHeatmap(tenantFindings, components);
  });

  // Tenant-wide component graph, bounded to the top 50 nodes by severity
  // (see `buildDependencyGraph`'s `cap` default) — not scoped to a single
  // SBOM id. `sbomId` is accepted and echoed back for the frontend's
  // `GraphData.sbomId` field only; it does not filter the graph.
  server.get('/security/graph', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = GraphQuerySchema.parse(req.query ?? {});
    const [tenantFindings, tenantSboms] = await Promise.all([
      findings.list(tenantId),
      sboms.list(tenantId),
    ]);
    return buildDependencyGraph(tenantSboms, tenantFindings, q.sbomId ?? 'tenant');
  });

  logger.debug('security-service analytics routes registered');
};
