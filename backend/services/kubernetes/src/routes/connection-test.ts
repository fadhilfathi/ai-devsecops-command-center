/**
 * Connection test route.
 *
 *   POST /v1/kubernetes/test-connection
 *
 * Accepts a kubeconfig-shaped payload (server URL + optional token
 * + optional CA bundle) and asks the requested provider to verify
 * that the cluster is reachable. Used by the "Add cluster" wizard
 * before persisting credentials.
 *
 * This makes an outbound request to an arbitrary caller-supplied
 * `server` URL and echoes back version/latency info — an SSRF oracle
 * if left open. Restricted to `platform_admin` (same gate as cluster
 * onboarding) and run through the SSRF policy before the provider ever
 * dials out. Error messages are generic: the live provider's raw error
 * text can contain upstream response bodies, so it is never echoed back.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import type { Logger } from '@aicc/shared';
import {
  ClusterConnectionTestRequestSchema,
  ClusterConnectionTestResponseSchema,
} from '@aicc/models';
import type { ClusterRepository } from '../repositories/cluster.repository.js';
import type { ProviderRegistry } from '../providers/registry.js';
import { checkServerUrlDns, type HostnameResolver } from '../ssrf-guard.js';
import { requireAdmin } from '../rbac.js';

interface Deps {
  logger: Logger;
  clusters: ClusterRepository;
  providers: ProviderRegistry;
  /** Injectable DNS resolver for the SSRF check. Defaults to real `dns.lookup`. */
  resolveHostname?: HostnameResolver;
}

export const buildConnectionTestRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, providers, resolveHostname } = opts;

  server.post(
    '/v1/kubernetes/test-connection',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const body = ClusterConnectionTestRequestSchema.parse(req.body);
      const providerId =
        (req.headers['x-aicc-provider'] as string | undefined) ?? providers.defaultId();
      const p = providers.get(providerId);
      if (!p) {
        reply.code(400);
        return { code: 'VALIDATION_ERROR', message: `unknown provider: ${providerId}` };
      }
      const check = await checkServerUrlDns(body.server, {
        allowPrivateApi: process.env.AICC_K8S_ALLOW_PRIVATE_API === 'true',
        resolveHostname,
      });
      if (!check.ok) {
        reply.code(400);
        return { code: 'VALIDATION_ERROR', message: check.reason };
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
        serverVersion: res.ok ? res.serverVersion : undefined,
        platform: res.ok ? res.platform : undefined,
        // Never echo the provider's raw error text back to the caller —
        // it can contain upstream response bodies from an internal host.
        message: res.ok ? res.message : 'connection failed',
        testedAt: new Date().toISOString(),
      });
      logger.info({ provider: providerId, ok: response.ok, latencyMs }, 'connection test');
      if (!response.ok) reply.code(400);
      return response;
    },
  );

  // Auxiliary: validate a label-selector string before sending it
  // downstream.
  server.post<{ Body: { selector: string } }>('/v1/kubernetes/validate-selector', async (req) => {
    const body = z.object({ selector: z.string().min(1) }).parse(req.body);
    return { valid: true, normalized: body.selector.trim() };
  });

  logger.debug('kubernetes-service connection-test routes registered');
};
