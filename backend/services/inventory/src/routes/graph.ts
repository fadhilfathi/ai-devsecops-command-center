/**
 * Graph routes.
 *
 *   GET /v1/inventory/graph/asset
 *   GET /v1/inventory/graph/relationships
 *   GET /v1/inventory/graph/dependencies
 *   GET /v1/inventory/graph/dependencies/:assetId
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { TopologyGraph } from '@aicc/models';
import type { InventoryEngine, InventoryEngineInput } from '../engine/inventory.engine.js';
import type { InventoryClient } from '../inventory/client.js';

interface Deps {
  logger: Logger;
  inventory: InventoryClient;
  engine: InventoryEngine;
  bus: EventBus;
}

const QuerySchema = z.object({
  clusterId: z.string().uuid().optional(),
  namespace: z.string().optional(),
  name: z.string().optional(),
});

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

async function snapshot(inventory: InventoryClient, tenantId: string, clusterId?: string): Promise<InventoryEngineInput> {
  return inventory.fetch(tenantId, clusterId);
}

function buildGraph(tenantId: string, name: string, clusterId: string | undefined, namespace: string | undefined, graph: { nodes: any[]; edges: any[] }): TopologyGraph {
  return {
    id: randomUUID(),
    tenantId,
    name,
    clusterId,
    namespace,
    nodes: graph.nodes,
    edges: graph.edges,
    generatedAt: new Date().toISOString(),
  };
}

export const buildGraphRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus } = opts;

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>(
    '/v1/inventory/graph/asset',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const snap = await snapshot(inventory, tenantId, q.clusterId);
      const graph = buildGraph(tenantId, 'unified-asset', q.clusterId, q.namespace, {
        nodes: engine.catalog(snap).map((a) => ({
          id: a.id, label: a.name, kind: a.kind, namespace: a.namespace,
          clusterId: a.clusterId, clusterName: a.clusterName, tags: Object.entries(a.labels).map(([k, v]) => `${k}=${v}`),
          metadata: a.metadata, riskScore: 0,
        })),
        edges: [],
      });
      return graph;
    },
  );

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>(
    '/v1/inventory/graph/relationships',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const snap = await snapshot(inventory, tenantId, q.clusterId);
      const g = engine.relationshipGraph(snap);
      return buildGraph(tenantId, 'relationship-graph', q.clusterId, q.namespace, g);
    },
  );

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>(
    '/v1/inventory/graph/dependencies',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const snap = await snapshot(inventory, tenantId, q.clusterId);
      const g = engine.dependencyGraph(snap);
      return buildGraph(tenantId, 'dependency-graph', q.clusterId, q.namespace, g);
    },
  );

  server.get<{
    Params: { assetId: string };
    Querystring: z.infer<typeof QuerySchema>;
  }>('/v1/inventory/graph/dependencies/:assetId', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    const g = engine.dependenciesFor(snap, req.params.assetId);
    return buildGraph(tenantId, 'dependency-subgraph', q.clusterId, q.namespace, g);
  });

  logger.debug('inventory-service graph routes registered');
  void bus;
};
