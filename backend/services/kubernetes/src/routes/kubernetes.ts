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
 *   GET /v1/kubernetes/providers   — auxiliary, lists available providers
 *
 * All routes are tenant-scoped. The `clusterId` query parameter
 * scopes the call to a single cluster; when omitted, AICC picks
 * the first onboarded cluster for the tenant.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { type EventBus, type Logger, type UUID } from '@aicc/shared';
import type {
  Cluster,
  ClusterListResponse,
  Namespace,
  NamespaceListResponse,
  Workload,
  WorkloadListResponse,
  Pod,
  PodListResponse,
  Service,
  ServiceListResponse,
  Ingress,
  IngressListResponse,
  Deployment,
  DeploymentListResponse,
  StatefulSet,
  StatefulSetListResponse,
  DaemonSet,
  DaemonSetListResponse,
} from '@aicc/models';
import type { ClusterRepository } from '../repositories/cluster.repository.js';
import type { KubernetesProvider, ProviderRegistry } from '../providers/registry.js';

interface Deps {
  logger: Logger;
  clusters: ClusterRepository;
  providers: ProviderRegistry;
  bus: EventBus;
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
  const found = requested
    ? clusters.find((c) => c.id === requested)
    : clusters[0];
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

export const buildKubernetesRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, clusters, providers, bus } = opts;

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

  logger.debug('kubernetes-service inventory routes registered');
  // Avoid unused-variable warnings while keeping the bus import
  // for future event publishing.
  void bus;
};
