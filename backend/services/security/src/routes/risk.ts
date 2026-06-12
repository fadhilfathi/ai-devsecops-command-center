/**
 * Risk calculation proxy route (S2.5).
 *
 *   POST /risk/calculate    — proxy to dependency-intel-service
 *
 * Endpoint:
 *   - Validate the request body with the S2.4 Zod schema
 *   - Apply RBAC: `platform_admin` or `security_engineer` only
 *   - Apply per-route rate limit: 10 req/s
 *   - Forward to dependency-intel-service (port 4009)
 *   - Publish `security.risk.calculated` for each risk weight in the
 *     returned graph
 */
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import { AppError, type EventBus, type Logger } from '@aicc/shared';
import {
  RiskCalculateRequestSchema,
  RiskCalculateResponseSchema,
  RISK_TOPIC,
  type SecurityRiskCalculatedEvent,
  toJSONSchema,
} from '@aicc/shared/security';
import { requireRole, requireTenantMatch } from '../middleware/rbac.js';
import { proxyRequest } from '../services/proxy.js';

interface Deps {
  logger: Logger;
  bus: EventBus;
  dependencyIntelUrl: string;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  serviceVersion: string;
}

export const buildRiskCalculateRoute: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, bus, dependencyIntelUrl, rateLimitMax, rateLimitWindowMs, serviceVersion } = opts;

  server.post<{ Body: unknown }>(
    '/risk/calculate',
    {
      preHandler: [requireRole('platform_admin', 'security_engineer'), requireTenantMatch],
      config: {
        rateLimit: { max: rateLimitMax, timeWindow: rateLimitWindowMs },
      },
      schema: {
        body: toJSONSchema(RiskCalculateRequestSchema),
        response: { 200: toJSONSchema(RiskCalculateResponseSchema) },
        tags: ['security', 'risk'],
        summary: 'Compute the dependency risk graph and composite risk scores for an SBOM',
        description: 'Proxies to dependency-intel-service (port 4009). Emits `security.risk.calculated` per risk weight.',
      },
    },
    async (req: FastifyRequest<{ Body: unknown }>, reply) => {
      const parsed = RiskCalculateRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new AppError('VALIDATION_ERROR', 'Invalid risk calculate request', {
          details: { issues: parsed.error.flatten() },
        });
      }
      const req_ = parsed.data;
      const tenantId = req_.tenantId ?? req.user!.tenantId;
      const proxyResult = await proxyRequest<unknown>({
        url: `${dependencyIntelUrl}/v1/risk/calculate`,
        method: 'POST',
        body: { ...req_, tenantId },
        logger,
        requestId: (req.headers['x-request-id'] as string) ?? undefined,
        serviceVersion,
      });

      const validated = RiskCalculateResponseSchema.safeParse(proxyResult.body);
      if (validated.success && validated.data.graph) {
        const graph = validated.data.graph;
        // Publish one event per top-5 riskiest component (deterministic
        // ordering by weight desc), plus a tenant-wide aggregate
        const sorted = [...graph.riskWeights].sort((a, b) => b.weight - a.weight).slice(0, 5);
        for (const w of sorted) {
          const event: SecurityRiskCalculatedEvent = {
            riskScoreId: `${graph.graphId}:${w.nodeId}`,
            tenantId,
            subjectKind: 'component',
            subjectId: w.nodeId,
            compositeScore: Math.round(w.weight * 100),
            computedAt: new Date().toISOString(),
            source: 'security-service',
          };
          await bus.publish({
            type: RISK_TOPIC,
            version: 1,
            source: 'security-service',
            tenantId,
            severity: w.weight > 0.7 ? 'high' : w.weight > 0.4 ? 'medium' : 'low',
            data: event,
          });
        }
        logger.info(
          {
            tenantId,
            graphId: graph.graphId,
            nodeCount: graph.nodes.length,
            edgeCount: graph.edges.length,
            topRisk: sorted[0]?.weight ?? 0,
          },
          'risk calculation complete',
        );
      }

      reply.code(proxyResult.status).send(proxyResult.body);
    },
  );

  logger.debug('security-service risk/calculate route registered');
};
