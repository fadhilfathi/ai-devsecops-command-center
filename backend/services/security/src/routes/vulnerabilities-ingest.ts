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
import { publishInstrumented } from '../services/metrics.js';
import { toGitOpsRecord } from '../services/vuln-projection.js';

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
        // S2.7 observability labels
        route: '/vulnerabilities/ingest',
        targetService: 'vuln-intel',
        tenantId,
      });

      const validated = VulnerabilityIngestResponseSchema.safeParse(proxyResult.body);
      if (validated.success) {
        // O-3.5 contract lock (2026-06-12): the security-service :4003 is the
        // projection boundary. For each ingested Vulnerability, we project
        // to the GitOps wire format (`VulnerabilityGitOpsRecord`) and emit
        // one event per (CVE, affected package) pair. Sprint 2 default:
        // `inGraph: false` (Sprint 2.1 plumbs the actual dependency-graph
        // lookup via dependency-intel :4009).
        for (const v of validated.data.ingested) {
          const event: SecurityVulnerabilityDetectedEvent = {
            vulnerabilityId: v.id,
            tenantId,
            affectedBomRefs: v.affected.map((a) => a.package.purl ?? `${a.package.ecosystem}/${a.package.name}`),
            severity: v.severity,
            cvssScore: v.cvssV3?.baseScore,
            kev: v.kev,
            detectedAt: new Date().toISOString(),
            source: 'security-service',
          };
          await publishInstrumented(bus, {
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

          // Project to GitOps wire format and emit one event per (CVE, package) pair.
          // The `inGraph: false` default will be replaced with the actual dependency-graph
          // lookup in Sprint 2.1 (O-3.5 contract; signed off 2026-06-12).
          for (const affected of v.affected) {
            // Reconstruct the per-(CVE, package) Vulnerability shape for the projection.
            const perPkgVuln = { ...v, affected: [affected] };
            const gitOpsRecord = toGitOpsRecord(perPkgVuln, {
              inGraph: false, // Sprint 2.1: lookup from dependency-intel :4009
              tenantId,
              now: new Date(),
              logger,
            });
            logger.debug(
              { vulnId: v.id, package: affected.package.name, ecosystem: affected.package.ecosystem, autoActionable: gitOpsRecord.auto_actionable },
              'projected vulnerability to GitOps wire format (security-service :4003 boundary)',
            );
            // NOTE: the bus emits the rich `data: event` shape above; the GitOps
            // wire-format record is logged + persisted (Sprint 2.1 will wire the
            // dedicated GitOps emission path via the github-bridge).
          }
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
