/**
 * Connection test route.
 *
 *   POST /v1/kubernetes/test-connection
 *
 * Accepts a kubeconfig-shaped payload (server URL + optional token
 * + optional CA bundle) and asks the requested provider to verify
 * that the cluster is reachable. Used by the "Add cluster" wizard
 * before persisting credentials.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { Logger } from '@aicc/shared';
import { ClusterConnectionTestRequestSchema, ClusterConnectionTestResponseSchema } from '@aicc/models';
import type { ClusterRepository } from '../repositories/cluster.repository.js';
import type { ProviderRegistry } from '../providers/registry.js';

interface Deps {
  logger: Logger;
  clusters: ClusterRepository;
  providers: ProviderRegistry;
}

export const buildConnectionTestRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, providers } = opts;

  server.post('/v1/kubernetes/test-connection', async (req, reply) => {
    const body = ClusterConnectionTestRequestSchema.parse(req.body);
    const providerId =
      (req.headers['x-aicc-provider'] as string | undefined) ?? providers.defaultId();
    const p = providers.get(providerId);
    if (!p) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: `unknown provider: ${providerId}` };
    }
    const started = Date.now();
    const res = await p.testConnection({
      server: body.server,
      token: body.token,
      caBundle: body.caBundle,
      insecureSkipVerify: body.insecureSkipVerify,
      name: body.name,
    });
    const latencyMs = res.latencyMs ?? Date.now() - started;
    const response = ClusterConnectionTestResponseSchema.parse({
      ok: res.ok,
      latencyMs,
      serverVersion: res.serverVersion,
      platform: res.platform,
      message: res.message,
      testedAt: new Date().toISOString(),
    });
    logger.info({ provider: providerId, ok: response.ok, latencyMs }, 'connection test');
    if (!response.ok) reply.code(400);
    return response;
  });

  // Auxiliary: validate a label-selector string before sending it
  // downstream.
  server.post<{ Body: { selector: string } }>('/v1/kubernetes/validate-selector', async (req) => {
    const body = z.object({ selector: z.string().min(1) }).parse(req.body);
    return { valid: true, normalized: body.selector.trim() };
  });

  logger.debug('kubernetes-service connection-test routes registered');
};
