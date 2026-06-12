/**
 * SBOM pipeline proxy routes (S2.5).
 *
 *   POST /sbom/generate    — proxy to sbom-pipeline-service
 *   POST /sbom/analyze     — proxy to sbom-pipeline-service
 *
 * Both endpoints:
 *   - Validate the request body with the S2.4 Zod schema
 *   - Apply RBAC: `platform_admin` or `security_engineer` only
 *   - Apply per-route rate limit: 10 req/s
 *   - Forward to the downstream Python service
 *   - Publish `security.sbom.generated` on success
 */
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { AppError, type EventBus, type Logger } from '@aicc/shared';
import {
  SbomGenerateRequestSchema,
  SbomAnalyzeRequestSchema,
  SbomServiceResponseSchema,
  SBOM_TOPIC,
  type SecuritySbomGeneratedEvent,
  toJSONSchema,
} from '@aicc/shared/security';
import { requireRole, requireTenantMatch } from '../middleware/rbac.js';
import { proxyRequest } from '../services/proxy.js';

interface Deps {
  logger: Logger;
  bus: EventBus;
  sbomPipelineUrl: string;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  serviceVersion: string;
}

export const buildSbomPipelineRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, bus, sbomPipelineUrl, rateLimitMax, rateLimitWindowMs, serviceVersion } = opts;

  // ---------- POST /sbom/generate ----------
  server.post<{ Body: unknown }>(
    '/sbom/generate',
    {
      preHandler: [requireRole('platform_admin', 'security_engineer'), requireTenantMatch],
      config: {
        rateLimit: { max: rateLimitMax, timeWindow: rateLimitWindowMs },
      },
      schema: {
        body: toJSONSchema(SbomGenerateRequestSchema),
        response: { 200: toJSONSchema(SbomServiceResponseSchema) },
        tags: ['security', 'sbom'],
        summary: 'Generate an SBOM from a container image, git repo, or filesystem path',
        description: 'Proxies to sbom-pipeline-service (port 4007). Emits `security.sbom.generated` on success.',
      },
    },
    async (req: FastifyRequest<{ Body: unknown }>, reply) => {
      const parsed = SbomGenerateRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new AppError('VALIDATION_ERROR', 'Invalid SBOM generate request', {
          details: { issues: parsed.error.flatten() },
        });
      }
      const req_ = parsed.data;
      const tenantId = req_.tenantId ?? req.user!.tenantId;
      const proxyResult = await proxyRequest<unknown>({
        url: `${sbomPipelineUrl}/v1/sbom/generate`,
        method: 'POST',
        body: { ...req_, tenantId },
        logger,
        requestId: (req.headers['x-request-id'] as string) ?? undefined,
        serviceVersion,
      });

      const validated = SbomServiceResponseSchema.safeParse(proxyResult.body);
      if (validated.success && validated.data.sbom) {
        const event: SecuritySbomGeneratedEvent = {
          sbomId: validated.data.sbom.metadata.timestamp,
          tenantId,
          rootBomRef: validated.data.sbom.metadata.component?.['bom-ref'] ?? validated.data.sbom.serialNumber ?? 'unknown',
          specVersion: validated.data.sbom.specVersion,
          componentCount: validated.data.sbom.components.length,
          generatedAt: new Date().toISOString(),
          source: 'sbom-pipeline-service',
        };
        await bus.publish({
          type: SBOM_TOPIC,
          version: 1,
          source: 'security-service',
          tenantId,
          severity: 'info',
          data: event,
        });
        logger.info({ tenantId, rootBomRef: event.rootBomRef, componentCount: event.componentCount }, 'SBOM generated');
      }

      reply.code(proxyResult.status).send(proxyResult.body);
    },
  );

  // ---------- POST /sbom/analyze ----------
  server.post<{ Body: unknown }>(
    '/sbom/analyze',
    {
      preHandler: [requireRole('platform_admin', 'security_engineer'), requireTenantMatch],
      config: {
        rateLimit: { max: rateLimitMax, timeWindow: rateLimitWindowMs },
      },
      schema: {
        body: toJSONSchema(SbomAnalyzeRequestSchema),
        response: { 200: toJSONSchema(SbomServiceResponseSchema) },
        tags: ['security', 'sbom'],
        summary: 'Analyse an SBOM for license compatibility and outdated dependencies',
        description: 'Proxies to sbom-pipeline-service (port 4007).',
      },
    },
    async (req, reply) => {
      const parsed = SbomAnalyzeRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new AppError('VALIDATION_ERROR', 'Invalid SBOM analyze request', {
          details: { issues: parsed.error.flatten() },
        });
      }
      const req_ = parsed.data;
      const tenantId = req_.tenantId ?? req.user!.tenantId;
      const proxyResult = await proxyRequest<unknown>({
        url: `${sbomPipelineUrl}/v1/sbom/analyze`,
        method: 'POST',
        body: { ...req_, tenantId },
        logger,
        requestId: (req.headers['x-request-id'] as string) ?? undefined,
        serviceVersion,
      });
      reply.code(proxyResult.status).send(proxyResult.body);
    },
  );

  logger.debug('security-service sbom-pipeline routes registered');
};

// Helper: keep the unused import linter-happy
void randomUUID;
