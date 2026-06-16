/**
 * Topology routes.
 *
 *   GET /v1/topology/graphs
 *   GET /v1/topology/service-map
 *   GET /v1/topology/application-graph
 *   GET /v1/topology/graph
 *   GET /v1/topology/namespace/:name
 *   GET /v1/topology/namespace-relationships
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { TopologyGraph } from '@aicc/models';
import type { TopologyEngine, TopologyEngineInput } from '../engine/topology.engine.js';
import type { InventoryClient } from '../inventory/client.js';

interface Deps { logger: Logger; inventory: InventoryClient; engine: TopologyEngine; bus: EventBus; }

const QuerySchema = z.object({ clusterId: z.string().uuid().optional() });

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

export const buildTopologyRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus } = opts;

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/topology/graphs', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const items: TopologyGraph[] = [
      engine.fullGraph(snap, 'topology', q.clusterId),
      engine.applicationGraph(snap, 'application', q.clusterId),
      engine.serviceMap(snap, 'service-map', q.clusterId),
    ];
    return { items, total: items.length };
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/topology/service-map', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    return engine.serviceMap(snap, 'service-map', q.clusterId);
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/topology/application-graph', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    return engine.applicationGraph(snap, 'application', q.clusterId);
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/topology/graph', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    return engine.fullGraph(snap, 'topology', q.clusterId);
  });

  server.get<{ Params: { name: string }; Querystring: z.infer<typeof QuerySchema> }>(
    '/v1/topology/namespace/:name',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const snap = await inventory.fetch(tenantId, q.clusterId);
      return engine.namespaceView(snap, req.params.name, `namespace:${req.params.name}`, q.clusterId);
    },
  );

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/topology/namespace-relationships', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    return engine.namespaceRelationships(snap, q.clusterId);
  });

  logger.debug('topology-service topology routes registered');
  void bus;
};
