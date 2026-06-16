/**
 * Report routes.
 *
 *   GET /v1/reports/cluster-health[?format=json|md|pdf]
 *   GET /v1/reports/infrastructure-risk[?format=json|md|pdf]
 *   GET /v1/reports/runtime-security[?format=json|md|pdf]
 *   GET /v1/reports/cost-optimization[?format=json|md|pdf]
 *   GET /v1/reports/topology[?format=json|md|pdf]
 *   GET /v1/reports/executive-summary[?format=json|md|pdf]
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { Report } from '../engine/report.engine.js';
import type { ReportEngine, ReportEngineInput } from '../engine/report.engine.js';
import type { InventoryClient } from '../inventory/client.js';
import { toJson, toMarkdown, toPdf, type ReportFormat } from '../formatters/format.js';

interface Deps { logger: Logger; inventory: InventoryClient; engine: ReportEngine; bus: EventBus; }

const QuerySchema = z.object({
  format: z.enum(['json', 'md', 'pdf']).default('json'),
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

function contentType(format: ReportFormat): string {
  if (format === 'json') return 'application/json; charset=utf-8';
  if (format === 'md') return 'text/markdown; charset=utf-8';
  return 'application/pdf';
}

function sendReport(reply: any, report: Report, format: ReportFormat, filename: string) {
  if (format === 'json') {
    reply.header('content-type', contentType(format));
    return toJson(report);
  }
  if (format === 'md') {
    reply.header('content-type', contentType(format));
    return toMarkdown(report);
  }
  reply.header('content-type', contentType(format));
  reply.header('content-disposition', `inline; filename="${filename}.pdf"`);
  return reply.send(toPdf(report));
}

export const buildReportRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, inventory, engine, bus } = opts;

  async function loadInput(tenantId: string, clusterId?: string): Promise<ReportEngineInput> {
    const data = await inventory.fetch(tenantId, clusterId);
    return {
      clusters: data.clusters,
      namespaces: data.namespaces,
      workloads: data.workloads,
      pods: data.pods,
      services: data.services,
      deployments: data.deployments,
      statefulsets: data.statefulsets,
      daemonsets: data.daemonsets,
      ingresses: data.ingresses,
      health: data.health,
      runtimeReport: data.runtimeReport,
      costAnalysis: data.costAnalysis,
      topology: data.topology,
    };
  }

  function makeHandler(fn: (input: ReportEngineInput) => Report, filename: string) {
    return async (req: any, reply: any) => {
      const tenantId = requireTenant(req.tenantId);
      const q = QuerySchema.parse(req.query ?? {});
      const input = await loadInput(tenantId, q.clusterId);
      const report = fn(input);
      logger.info({ tenantId, kind: report.kind, format: q.format }, 'report generated');
      return sendReport(reply, report, q.format, filename);
    };
  }

  server.get('/v1/reports/cluster-health', makeHandler((i) => engine.clusterHealth(i), 'cluster-health'));
  server.get('/v1/reports/infrastructure-risk', makeHandler((i) => engine.infrastructureRisk(i), 'infrastructure-risk'));
  server.get('/v1/reports/runtime-security', makeHandler((i) => engine.runtimeSecurity(i), 'runtime-security'));
  server.get('/v1/reports/cost-optimization', makeHandler((i) => engine.costOptimization(i), 'cost-optimization'));
  server.get('/v1/reports/topology', makeHandler((i) => engine.topology(i), 'topology'));
  server.get('/v1/reports/executive-summary', makeHandler((i) => engine.executiveSummary(i), 'executive-summary'));

  // Catalogue endpoint (Sprint 5 will add a report-schedule UI here).
  server.get('/v1/reports', async () => ({
    items: [
      { kind: 'cluster_health', path: '/v1/reports/cluster-health' },
      { kind: 'infrastructure_risk', path: '/v1/reports/infrastructure-risk' },
      { kind: 'runtime_security', path: '/v1/reports/runtime-security' },
      { kind: 'cost_optimization', path: '/v1/reports/cost-optimization' },
      { kind: 'topology', path: '/v1/reports/topology' },
      { kind: 'executive_summary', path: '/v1/reports/executive-summary' },
    ],
    formats: ['json', 'md', 'pdf'],
  }));

  logger.debug('reporting-service report routes registered');
  void bus;
};
