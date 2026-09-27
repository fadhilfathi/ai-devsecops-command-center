/**
 * Kubernetes inventory routes.
 *
 * Mounts:
 *   GET /v1/kubernetes/clusters
 *   GET /v1/kubernetes/namespaces
 *   GET /v1/kubernetes/workloads
 *   GET /v1/kubernetes/pods
 *   GET /v1/kubernetes/services
 *   GET /v1/kubernetes/ingresses
 *   GET /v1/kubernetes/deployments
 *   GET /v1/kubernetes/statefulsets
 *   GET /v1/kubernetes/daemonsets
 *   GET /v1/kubernetes/network-policies
 *   GET /v1/kubernetes/providers   — auxiliary, lists available providers
 *
 * All routes are tenant-scoped. The `clusterId` query parameter
 * scopes the call to a single cluster; when omitted, AICC picks
 * the first onboarded cluster for the tenant.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import {
  ClusterCreateRequestSchema,
  ClusterUpdateRequestSchema,
  type Cluster,
  type ClusterListResponse,
  type NamespaceListResponse,
  type Workload,
  type WorkloadListResponse,
  type Pod,
  type PodListResponse,
  type Service,
  type ServiceListResponse,
  type Ingress,
  type IngressListResponse,
  type Deployment,
  type DeploymentListResponse,
  type StatefulSet,
  type StatefulSetListResponse,
  type DaemonSet,
  type DaemonSetListResponse,
  type NetworkPolicy,
  type NetworkPolicyListResponse,
} from '@aicc/models';
import type { ClusterRepository } from '../repositories/cluster.repository.js';
import type { KubernetesProvider, ProviderRegistry } from '../providers/registry.js';
import { checkServerUrlDns, type HostnameResolver } from '../ssrf-guard.js';
import { requireAdmin } from '../rbac.js';

interface Deps {
  logger: Logger;
  clusters: ClusterRepository;
  providers: ProviderRegistry;
  bus: EventBus;
  /** Injectable DNS resolver for the SSRF check on cluster onboarding. Defaults to real `dns.lookup`. */
  resolveHostname?: HostnameResolver;
}

const ListQuerySchema = z.object({
  clusterId: z.string().uuid().optional(),
  namespace: z.string().optional(),
  labelSelector: z.string().optional(),
  provider: z.string().optional(),
});

function pickCluster<T>(clusters: Cluster[], requested: string | undefined): T {
  // The list calls share the same shape: a "subject" cluster. We
  // return the matching cluster, or the first one if only one is
  // available, or throw 404.
  const found = requested ? clusters.find((c) => c.id === requested) : clusters[0];
  if (!found) {
    const e = new Error('no cluster available for this tenant') as Error & { statusCode?: number };
    e.statusCode = 404;
    throw e;
  }
  return found as unknown as T;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

async function getProvider(
  providers: ProviderRegistry,
  clusterId: string,
  clusters: ClusterRepository,
  tenantId: string,
  requested: string | undefined,
): Promise<KubernetesProvider> {
  const providerId =
    (requested ? providers.get(requested)?.id : undefined) ??
    (await clusters.getProviderIdForCluster(clusterId, tenantId)) ??
    providers.defaultId();
  const p = providers.get(providerId);
  if (!p) {
    const e = new Error(`unknown provider: ${providerId}`) as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return p;
}

export const buildKubernetesRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, clusters, providers, bus, resolveHostname } = opts;

  // ---- providers (auxiliary) -------------------------------------------
  server.get('/v1/kubernetes/providers', async () => ({
    items: providers.list().map((p) => ({ id: p.id, name: p.name, readOnly: p.readOnly })),
    defaultId: providers.defaultId(),
  }));

  // ---- clusters --------------------------------------------------------
  server.get<{ Reply: ClusterListResponse }>('/v1/kubernetes/clusters', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const items = await clusters.list(tenantId);
    logger.debug({ count: items.length }, 'listed clusters');
    return { items, total: items.length };
  });

  server.post<{ Reply: Cluster }>(
    '/v1/kubernetes/clusters',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const tenantId = requireTenant(req.tenantId);
      const body = ClusterCreateRequestSchema.parse(req.body);
      // `ClusterProviderSchema` (the real cloud-vendor enum) never includes
      // 'fixture' — fixture clusters are seeded in code, not onboarded via
      // this API — so every request here is checked against the SSRF policy.
      const check = await checkServerUrlDns(body.server, {
        allowPrivateApi: process.env.AICC_K8S_ALLOW_PRIVATE_API === 'true',
        resolveHostname,
      });
      if (!check.ok) {
        const e = new Error(check.reason) as Error & { statusCode?: number };
        e.statusCode = 400;
        throw e;
      }
      const cluster = await clusters.create({ tenantId, ...body });
      logger.info({ clusterId: cluster.id }, 'cluster created');
      reply.code(201);
      return cluster;
    },
  );

  server.patch<{ Params: { id: string }; Reply: Cluster }>(
    '/v1/kubernetes/clusters/:id',
    { preHandler: requireAdmin },
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      const body = ClusterUpdateRequestSchema.parse(req.body);
      const updated = await clusters.update(req.params.id as UUID, tenantId, body);
      if (!updated) {
        const e = new Error('cluster not found') as Error & { statusCode?: number };
        e.statusCode = 404;
        throw e;
      }
      // A credential rotation changes the connection fingerprint, so the
      // next call naturally rebuilds the live client (see LiveProvider);
      // evicting here just frees the stale entry a little sooner.
      providers.evictLive(tenantId, updated.id);
      logger.info({ clusterId: updated.id }, 'cluster updated');
      return updated;
    },
  );

  server.delete<{ Params: { id: string } }>(
    '/v1/kubernetes/clusters/:id',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const tenantId = requireTenant(req.tenantId);
      const removed = await clusters.remove(req.params.id as UUID, tenantId);
      if (!removed) {
        const e = new Error('cluster not found') as Error & { statusCode?: number };
        e.statusCode = 404;
        throw e;
      }
      providers.evictLive(tenantId, req.params.id);
      logger.info({ clusterId: req.params.id }, 'cluster deleted');
      reply.code(204);
    },
  );

  // ---- namespaces ------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: NamespaceListResponse;
  }>('/v1/kubernetes/namespaces', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items = await p.listNamespaces(tenantId, cluster.id);
    return { items, total: items.length };
  });

  // ---- workloads -------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: WorkloadListResponse;
  }>('/v1/kubernetes/workloads', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: Workload[] = await p.listWorkloads(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- pods ------------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: PodListResponse;
  }>('/v1/kubernetes/pods', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: Pod[] = await p.listPods(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- services --------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: ServiceListResponse;
  }>('/v1/kubernetes/services', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: Service[] = await p.listServices(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- ingresses -------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: IngressListResponse;
  }>('/v1/kubernetes/ingresses', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: Ingress[] = await p.listIngresses(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- deployments -----------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: DeploymentListResponse;
  }>('/v1/kubernetes/deployments', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: Deployment[] = await p.listDeployments(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- statefulsets ----------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: StatefulSetListResponse;
  }>('/v1/kubernetes/statefulsets', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: StatefulSet[] = await p.listStatefulSets(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- daemonsets ------------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: DaemonSetListResponse;
  }>('/v1/kubernetes/daemonsets', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: DaemonSet[] = await p.listDaemonSets(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  // ---- network policies -------------------------------------------------
  server.get<{
    Querystring: z.infer<typeof ListQuerySchema>;
    Reply: NetworkPolicyListResponse;
  }>('/v1/kubernetes/network-policies', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const q = ListQuerySchema.parse(req.query ?? {});
    const all = await clusters.list(tenantId);
    const cluster = pickCluster<Cluster>(all, q.clusterId);
    const p = await getProvider(providers, cluster.id, clusters, tenantId, q.provider);
    const items: NetworkPolicy[] = await p.listNetworkPolicies(tenantId, {
      clusterId: cluster.id,
      namespace: q.namespace,
      labelSelector: q.labelSelector,
    });
    return { items, total: items.length };
  });

  logger.debug('kubernetes-service inventory routes registered');
  // Avoid unused-variable warnings while keeping the bus import
  // for future event publishing.
  void bus;
};
