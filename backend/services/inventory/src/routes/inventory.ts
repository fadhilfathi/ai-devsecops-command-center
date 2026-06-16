/**
 * Inventory routes — asset catalog + per-kind inventories.
 *
 *   GET /v1/inventory/assets
 *   GET /v1/inventory/assets/:id
 *   GET /v1/inventory/clusters
 *   GET /v1/inventory/namespaces
 *   GET /v1/inventory/services
 *   GET /v1/inventory/deployments
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { Asset, InventoryEngine, InventoryEngineInput } from '../engine/inventory.engine.js';
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
  kind: z.enum(['cluster', 'namespace', 'service', 'deployment', 'statefulset', 'daemonset', 'ingress', 'workload', 'pod']).optional(),
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
  const s = await inventory.fetch(tenantId, clusterId);
  return s;
}

export const buildInventoryRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus } = opts;

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/inventory/assets', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    let items = engine.catalog(snap);
    if (q.namespace) items = items.filter((a: Asset) => a.namespace === q.namespace);
    if (q.kind) items = items.filter((a) => a.kind === q.kind);
    return { items, total: items.length };
  });

  server.get<{ Params: { id: string } }>('/v1/inventory/assets/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const snap = await snapshot(inventory, tenantId);
    const item = engine.catalog(snap).find((a) => a.id === req.params.id);
    if (!item) {
      const e = new Error('asset not found') as Error & { statusCode?: number };
      e.statusCode = 404;
      throw e;
    }
    return { asset: item };
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/inventory/clusters', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    return { items: snap.clusters, total: snap.clusters.length };
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/inventory/namespaces', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    let items = snap.namespaces;
    if (q.namespace) items = items.filter((n) => n.name === q.namespace);
    return { items, total: items.length };
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/inventory/services', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    let items = snap.services;
    if (q.namespace) items = items.filter((s) => s.namespace === q.namespace);
    return { items, total: items.length };
  });

  server.get<{ Querystring: z.infer<typeof QuerySchema> }>('/v1/inventory/deployments', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await snapshot(inventory, tenantId, q.clusterId);
    let items = snap.deployments;
    if (q.namespace) items = items.filter((d) => d.namespace === q.namespace);
    return { items, total: items.length };
  });

  logger.debug('inventory-service inventory routes registered');
  void bus;
};
