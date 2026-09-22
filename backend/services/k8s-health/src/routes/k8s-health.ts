/**
 * K8s health routes.
 *
 *   GET /v1/health/clusters
 *   GET /v1/health/namespaces
 *   GET /v1/health/workloads
 *   GET /v1/health/pods
 *   GET /v1/health/clusters/:id
 *   GET /v1/health/issues
 *   GET /v1/health/recommendations
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EventTypes, type EventBus, type Logger, type UUID } from '@aicc/shared';
import type {
  InfrastructureHealth,
  InfrastructureHealthListResponse,
  HealthIssue,
  HealthRecommendation,
} from '@aicc/models';
import type { HealthEngine, HealthEngineInput } from '../engine/health-engine.js';
import type { InventoryClient } from '../inventory/client.js';

interface Deps {
  logger: Logger;
  inventory: InventoryClient;
  engine: HealthEngine;
  bus: EventBus;
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

async function loadInput(
  inventory: InventoryClient,
  tenantId: string,
  clusterId?: string,
): Promise<HealthEngineInput> {
  const snap = await inventory.fetch(tenantId, clusterId);
  return {
    clusters: snap.clusters,
    namespaces: snap.namespaces,
    workloads: snap.workloads,
    pods: snap.pods,
  };
}

export const buildK8sHealthRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, inventory, engine, bus } = opts;

  server.get<{ Reply: InfrastructureHealthListResponse }>('/v1/health/clusters', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const input = await loadInput(inventory, tenantId);
    const items = engine.score(input).filter((h) => h.scope === 'cluster');
    return { items, total: items.length };
  });

  server.get<{ Reply: InfrastructureHealthListResponse }>('/v1/health/namespaces', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const input = await loadInput(inventory, tenantId);
    const items = engine.score(input).filter((h) => h.scope === 'namespace');
    return { items, total: items.length };
  });

  server.get<{ Reply: InfrastructureHealthListResponse }>('/v1/health/workloads', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const input = await loadInput(inventory, tenantId);
    const items = engine.score(input).filter((h) => h.scope === 'workload');
    return { items, total: items.length };
  });

  server.get<{ Reply: InfrastructureHealthListResponse }>('/v1/health/pods', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const input = await loadInput(inventory, tenantId);
    const items = engine.score(input).filter((h) => h.scope === 'pod');
    return { items, total: items.length };
  });

  server.get<{
    Params: { id: string };
    Querystring: z.infer<typeof QuerySchema>;
  }>('/v1/health/clusters/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const input = await loadInput(inventory, tenantId, q.clusterId ?? req.params.id);
    const items = engine
      .score(input)
      .filter((h) => h.scope === 'cluster' && h.subject.clusterId === req.params.id);
    const item = items[0] as InfrastructureHealth | undefined;
    if (!item) {
      const e = new Error('cluster not found') as Error & { statusCode?: number };
      e.statusCode = 404;
      throw e;
    }
    return item;
  });

  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: { items: HealthIssue[]; total: number };
  }>('/v1/health/issues', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const input = await loadInput(inventory, tenantId, q.clusterId);
    const issues = engine.collectIssues(input);

    // Publish one batched event per request (not one per issue) so the
    // compliance service can auto-map every issue to CIS/NIST controls
    // (S6-4) without the publish work blocking the response. This GET
    // republishes the same open issues on every poll — evidence is
    // deduped downstream by blob ref (see EvidenceAttacher), so cheap,
    // frequent, batched publishing is fine here.
    // ponytail: fire-and-forget, logged on rejection — never await in the
    // request path.
    if (issues.length > 0) {
      void bus
        .publish({
          type: EventTypes.CLUSTER_HEALTH_ISSUE_DETECTED,
          version: 1,
          source: 'k8s-health-service',
          tenantId,
          data: { findings: issues },
        })
        .catch((err) => {
          logger.error(
            { err, count: issues.length },
            'failed to publish cluster.health.issue.detected',
          );
        });
    }

    return { items: issues, total: issues.length };
  });

  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: { items: HealthRecommendation[]; total: number };
  }>('/v1/health/recommendations', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const input = await loadInput(inventory, tenantId, q.clusterId);
    const issues = engine.collectIssues(input);
    const recs = engine.recommend(input, issues);
    return { items: recs, total: recs.length };
  });

  logger.debug('k8s-health-service health routes registered');
};
