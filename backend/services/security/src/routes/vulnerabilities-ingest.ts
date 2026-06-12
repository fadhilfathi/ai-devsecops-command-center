/**
 * Vulnerability ingest proxy route (S2.5).
 *
 *   POST /vulnerabilities/ingest    — proxy to vuln-intel-service
 *
 * Endpoint:
 *   - Validate the request body with the S2.4 Zod schema
 *   - Apply RBAC: `platform_admin` or `security_engineer` only
 *   - Apply per-route rate limit: 10 req/s
 *   - Forward to vuln-intel-service (port 4008)
 *   - Publish `security.vulnerability.detected` for each newly
 *     ingested vulnerability (severity → bus severity)
 */
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import { AppError, type EventBus, type Logger } from '@aicc/shared';
import {
  VulnerabilityIngestRequestSchema,
  VulnerabilityIngestResponseSchema,
  VULN_TOPIC,
  type SecurityVulnerabilityDetectedEvent,
  toJSONSchema,
} from '@aicc/shared/security';
import { requireRole, requireTenantMatch } from '../middleware/rbac.js';
import { proxyRequest } from '../services/proxy.js';

interface Deps {
  logger: Logger;
  bus: EventBus;
  vulnIntelUrl: string;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  serviceVersion: string;
}

export const buildVulnerabilityIngestRoute: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, bus, vulnIntelUrl, rateLimitMax, rateLimitWindowMs, serviceVersion } = opts;

  server.post<{ Body: unknown }>(
    '/vulnerabilities/ingest',
    {
      preHandler: [requireRole('platform_admin', 'security_engineer'), requireTenantMatch],
      config: {
        rateLimit: { max: rateLimitMax, timeWindow: rateLimitWindowMs },
      },
      schema: {
        body: toJSONSchema(VulnerabilityIngestRequestSchema),
        response: { 200: toJSONSchema(VulnerabilityIngestResponseSchema) },
        tags: ['security', 'vulnerabilities'],
        summary: 'Ingest vulnerabilities by id (CVE/GHSA/OSV) and normalise across sources',
        description: 'Proxies to vuln-intel-service (port 4008). Emits `security.vulnerability.detected` for each ingested vulnerability.',
      },
    },
    async (req: FastifyRequest<{ Body: unknown }>, reply) => {
      const parsed = VulnerabilityIngestRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new AppError('VALIDATION_ERROR', 'Invalid vulnerability ingest request', {
          details: { issues: parsed.error.flatten() },
        });
      }
      const req_ = parsed.data;
      const tenantId = req_.tenantId ?? req.user!.tenantId;
      const proxyResult = await proxyRequest<unknown>({
        url: `${vulnIntelUrl}/v1/vulnerabilities/ingest`,
        method: 'POST',
        body: { ...req_, tenantId },
        logger,
        requestId: (req.headers['x-request-id'] as string) ?? undefined,
        serviceVersion,
      });

      const validated = VulnerabilityIngestResponseSchema.safeParse(proxyResult.body);
      if (validated.success) {
        for (const v of validated.data.ingested) {
          // Pick the worst affected component to anchor the event
          const affectedBomRefs = v.affected.map((a) => a.package.purl ?? `${a.package.ecosystem}/${a.package.name}`);
          const event: SecurityVulnerabilityDetectedEvent = {
            vulnerabilityId: v.id,
            tenantId,
            affectedBomRefs,
            severity: v.severity,
            cvssScore: v.cvssV3?.baseScore,
            kev: v.kev,
            detectedAt: new Date().toISOString(),
            source: 'security-service',
          };
          await bus.publish({
            type: VULN_TOPIC,
            version: 1,
            source: 'security-service',
            tenantId,
            severity: v.severity === 'critical' ? 'critical' :
                      v.severity === 'high' ? 'high' :
                      v.severity === 'medium' ? 'medium' :
                      v.severity === 'low' ? 'low' : 'info',
            data: event,
          });
        }
        logger.info(
          {
            tenantId,
            ingested: validated.data.ingested.length,
            failed: validated.data.failed.length,
          },
          'vulnerability ingest complete',
        );
      }

      reply.code(proxyResult.status).send(proxyResult.body);
    },
  );

  logger.debug('security-service vulnerabilities/ingest route registered');
};
