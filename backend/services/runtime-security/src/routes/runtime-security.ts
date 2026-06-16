/**
 * Runtime security routes.
 *
 *   GET    /v1/runtime-security/risks
 *   GET    /v1/runtime-security/risks/:id
 *   POST   /v1/runtime-security/scan
 *   GET    /v1/runtime-security/report
 *   GET    /v1/runtime-security/report/cluster/:id
 *   GET    /v1/runtime-security/rules
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type {
  RuntimeRisk,
  RuntimeRiskListResponse,
  RuntimeSecurityReport,
} from '@aicc/models';
import type { RuntimeSecurityEngine } from '../engine/runtime-security.engine.js';
import type { InventoryClient } from '../inventory/client.js';

interface Deps {
  logger: Logger;
  inventory: InventoryClient;
  engine: RuntimeSecurityEngine;
  bus: EventBus;
}

const QuerySchema = z.object({
  clusterId: z.string().uuid().optional(),
  namespace: z.string().optional(),
  level: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  category: z.string().optional(),
  ruleId: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(500),
});

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

export const buildRuntimeSecurityRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus } = opts;

  // ---- rules ---------------------------------------------------------
  server.get('/v1/runtime-security/rules', async () => ({
    items: engine.listRules().map((r) => ({
      id: r.id,
      name: r.name,
      category: r.category,
      level: r.level,
      severity: r.severity,
      remediation: r.remediation,
      references: r.references,
    })),
    total: engine.listRules().length,
  }));

  // ---- risks ---------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
    Reply: RuntimeRiskListResponse;
  }>('/v1/runtime-security/risks', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const findings: RuntimeRisk[] = [];
    for (const cluster of snap.clusters) {
      const report = engine.report(
        {
          tenantId,
          clusterId: cluster.id,
          clusterName: cluster.name,
          pods: snap.pods.filter((p) => p.clusterId === cluster.id),
          workloads: snap.workloads.filter((w) => w.clusterId === cluster.id),
          services: snap.services.filter((s) => s.clusterId === cluster.id),
        },
        new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString(),
      );
      findings.push(...report.findings);
    }
    let filtered = findings;
    if (q.namespace) filtered = filtered.filter((f) => f.namespace === q.namespace);
    if (q.level) filtered = filtered.filter((f) => f.level === q.level);
    if (q.category) filtered = filtered.filter((f) => f.category === q.category);
    if (q.ruleId) filtered = filtered.filter((f) => f.ruleId === q.ruleId);
    const items = filtered.slice(0, q.limit);
    return { items, total: items.length };
  });

  server.get<{ Params: { id: string } }>('/v1/runtime-security/risks/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    for (const cluster of snap.clusters) {
      const report = engine.report(
        {
          tenantId,
          clusterId: cluster.id,
          clusterName: cluster.name,
          pods: snap.pods.filter((p) => p.clusterId === cluster.id),
          workloads: snap.workloads.filter((w) => w.clusterId === cluster.id),
          services: snap.services.filter((s) => s.clusterId === cluster.id),
        },
        new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString(),
      );
      const hit = report.findings.find((f) => f.id === req.params.id);
      if (hit) return hit;
    }
    const e = new Error('risk not found') as Error & { statusCode?: number };
    e.statusCode = 404;
    throw e;
  });

  // ---- scan ----------------------------------------------------------
  server.post('/v1/runtime-security/scan', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const body = z
      .object({ clusterId: z.string().uuid().optional() })
      .parse(req.body ?? {});
    const snap = await inventory.fetch(tenantId, body.clusterId);
    const totalFindings = snap.clusters.reduce((acc, cluster) => {
      const report = engine.report(
        {
          tenantId, clusterId: cluster.id, clusterName: cluster.name,
          pods: snap.pods.filter((p) => p.clusterId === cluster.id),
          workloads: snap.workloads.filter((w) => w.clusterId === cluster.id),
          services: snap.services.filter((s) => s.clusterId === cluster.id),
        },
        new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString(),
      );
      return acc + report.findings.length;
    }, 0);
    logger.info({ tenantId, clusterId: body.clusterId, totalFindings }, 'runtime security scan completed');
    reply.code(202);
    return { accepted: true, totalFindings };
  });

  // ---- reports -------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof QuerySchema>;
  }>('/v1/runtime-security/report', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = QuerySchema.parse(req.query ?? {});
    const snap = await inventory.fetch(tenantId, q.clusterId);
    const reports: RuntimeSecurityReport[] = [];
    for (const cluster of snap.clusters) {
      reports.push(engine.report(
        {
          tenantId, clusterId: cluster.id, clusterName: cluster.name,
          pods: snap.pods.filter((p) => p.clusterId === cluster.id),
          workloads: snap.workloads.filter((w) => w.clusterId === cluster.id),
          services: snap.services.filter((s) => s.clusterId === cluster.id),
        },
        new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString(),
      ));
    }
    return { items: reports, total: reports.length };
  });

  server.get<{ Params: { id: string } }>(
    '/v1/runtime-security/report/cluster/:id',
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const snap = await inventory.fetch(tenantId, req.params.id);
      const cluster = snap.clusters.find((c) => c.id === req.params.id);
      if (!cluster) {
        const e = new Error('cluster not found') as Error & { statusCode?: number };
        e.statusCode = 404;
        throw e;
      }
      return engine.report(
        {
          tenantId, clusterId: cluster.id, clusterName: cluster.name,
          pods: snap.pods.filter((p) => p.clusterId === cluster.id),
          workloads: snap.workloads.filter((w) => w.clusterId === cluster.id),
          services: snap.services.filter((s) => s.clusterId === cluster.id),
        },
        new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        new Date().toISOString(),
      );
    },
  );

  logger.debug('runtime-security-service routes registered');
  void bus;
};
