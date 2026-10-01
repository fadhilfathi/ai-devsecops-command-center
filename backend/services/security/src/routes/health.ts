import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { EventBus, Logger } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

interface Deps {
  logger: Logger;
  cfg: { name: string; version: string };
  bus?: EventBus;
  db?: Queryable;
  // S8-5: the three Python agent URLs, checked as part of /readyz so a
  // misconfigured/down agent fleet is visible without calling each proxy
  // route. Health paths are liveness-only (no outbound network calls of
  // their own), so this stays fast and CI-safe.
  sbomPipelineUrl?: string;
  vulnIntelUrl?: string;
  dependencyIntelUrl?: string;
}

async function checkUpstream(baseUrl: string, path: string): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(2_000) });
    return res.ok;
  } catch {
    return false;
  }
}

export const buildHealthRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, cfg, bus, db, sbomPipelineUrl, vulnIntelUrl, dependencyIntelUrl } = opts;
  const startedAt = new Date();

  server.get('/healthz', async () => ({ status: 'ok' }));
  server.get('/readyz', async (_req, reply) => {
    if (bus?.ping) {
      try {
        await bus.ping();
      } catch (err) {
        logger.error({ err }, 'readyz: event bus check failed');
        return reply.code(503).send({ status: 'not_ready' });
      }
    }

    if (db) {
      try {
        await db.query('SELECT 1');
      } catch (err) {
        logger.error({ err }, 'readyz: postgres check failed');
        return reply.code(503).send({ status: 'not_ready' });
      }
    }

    const upstreams: Record<string, boolean> = {};
    if (sbomPipelineUrl) upstreams.sbomPipeline = await checkUpstream(sbomPipelineUrl, '/healthz');
    if (vulnIntelUrl) upstreams.vulnIntel = await checkUpstream(vulnIntelUrl, '/livez');
    if (dependencyIntelUrl)
      upstreams.dependencyIntel = await checkUpstream(dependencyIntelUrl, '/livez');

    const upstreamsChecked = Object.keys(upstreams).length > 0;
    const allUpstreamsOk = Object.values(upstreams).every(Boolean);
    if (upstreamsChecked && !allUpstreamsOk) {
      logger.error({ upstreams }, 'readyz: one or more upstream agents unreachable');
      return reply.code(503).send({ status: 'not_ready', upstreams });
    }

    return {
      status: 'ready',
      service: cfg.name,
      version: cfg.version,
      uptimeSeconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
      checks: { process: { status: 'healthy' } },
      ...(upstreamsChecked ? { upstreams } : {}),
    };
  });
  server.get('/version', async () => ({
    service: cfg.name,
    version: cfg.version,
    startedAt: startedAt.toISOString(),
  }));
  logger.debug('security-service health routes registered');
};
