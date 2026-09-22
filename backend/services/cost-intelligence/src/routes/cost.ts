/**
 * Cost routes.
 *
 *   GET /v1/cost/analysis
 *   GET /v1/cost/analysis/cluster/:id
 *   GET /v1/cost/workloads
 *   GET /v1/cost/findings
 *   GET /v1/cost/recommendations
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type {
  CostAnalysis,
  CostAnalysisListResponse,
  WorkloadCost,
  CostFinding,
  CostRecommendation,
} from '@aicc/models';
import type { CostEngine, CostEngineInput } from '../engine/cost.engine.js';
import type { InventoryClient, InventorySnapshot } from '../inventory/client.js';
import type { UtilisationSource } from '../utilisation/source.js';

interface Deps {
  logger: Logger;
  inventory: InventoryClient;
  engine: CostEngine;
  bus: EventBus;
  utilisationSource: UtilisationSource;
}

const QuerySchema = z.object({
  clusterId: z.string().uuid().optional(),
  namespace: z.string().optional(),
});

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

function window(): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

export const buildCostRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus, utilisationSource } = opts;

  async function analyseCluster(
    tenantId: string,
    cluster: { id: string; name: string },
    snap: InventorySnapshot,
    start: string,
    end: string,
  ): Promise<CostAnalysis> {
    const workloads = snap.workloads.filter((w) => w.clusterId === cluster.id);
    const pods = snap.pods.filter((p) => p.clusterId === cluster.id);
    const { utilisation, kind } = await utilisationSource.fetch({
      tenantId,
      clusterId: cluster.id,
      workloads,
      pods,
      windowStart: start,
      windowEnd: end,
    });
    const input: CostEngineInput = {
      tenantId,
      clusterId: cluster.id,
      clusterName: cluster.name,
      workloads,
      utilisation,
      utilisationSource: kind,
    };
    return engine.analyse(input, start, end);
  }

  server.get<{ Querystring: z.infer<typeof QuerySchema>; Reply: CostAnalysisListResponse }>(
    '/v1/cost/analysis',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const snap = await inventory.fetch(tenantId, q.clusterId);
      const { start, end } = window();
      const items: CostAnalysis[] = await Promise.all(
        snap.clusters.map((c) => analyseCluster(tenantId, c, snap, start, end)),
      );
      return { items, total: items.length };
    },
  );

  server.get<{ Params: { id: string } }>('/v1/cost/analysis/cluster/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const snap = await inventory.fetch(tenantId, req.params.id);
    const cluster = snap.clusters.find((c) => c.id === req.params.id);
    if (!cluster) {
      const e = new Error('cluster not found') as Error & { statusCode?: number };
      e.statusCode = 404;
      throw e;
    }
    const { start, end } = window();
    return analyseCluster(tenantId, cluster, snap, start, end);
  });

  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: { items: WorkloadCost[]; total: number };
  }>('/v1/cost/workloads', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const { start, end } = window();
    const analyses = await Promise.all(
      snap.clusters.map((cluster) => analyseCluster(tenantId, cluster, snap, start, end)),
    );
    const items: WorkloadCost[] = [];
    for (const a of analyses) {
      for (const wc of a.workloads) {
        if (q.namespace && wc.namespace !== q.namespace) continue;
        items.push(wc);
      }
    }
    return { items, total: items.length };
  });

  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: { items: CostFinding[]; total: number };
  }>('/v1/cost/findings', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const { start, end } = window();
    const analyses = await Promise.all(
      snap.clusters.map((cluster) => analyseCluster(tenantId, cluster, snap, start, end)),
    );
    const items: CostFinding[] = analyses.flatMap((a) => a.findings);
    return { items, total: items.length };
  });

  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: { items: CostRecommendation[]; total: number };
  }>('/v1/cost/recommendations', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const { start, end } = window();
    const analyses = await Promise.all(
      snap.clusters.map((cluster) => analyseCluster(tenantId, cluster, snap, start, end)),
    );
    const allRecs: CostRecommendation[] = analyses.flatMap((a) => a.recommendations);
    // Dedup by (title, action) keeping the highest-priority entry.
    const map = new Map<string, CostRecommendation>();
    for (const r of allRecs) {
      const k = `${r.action}::${r.title}`;
      if (!map.has(k) || map.get(k)!.priority.localeCompare(r.priority) > 0) {
        map.set(k, r);
      }
    }
    const items = Array.from(map.values()).sort((a, b) => a.priority.localeCompare(b.priority));
    return { items, total: items.length };
  });

  logger.debug('cost-intelligence-service cost routes registered');
  void bus;
};
