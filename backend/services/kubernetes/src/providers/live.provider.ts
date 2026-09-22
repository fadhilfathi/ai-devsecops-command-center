/**
 * Live Kubernetes provider — Sprint 5.
 *
 * Talks to a real Kubernetes API server via `@kubernetes/client-node`.
 * Read-only: only `list*` and `getCode` calls are issued. One client
 * set is built per cluster and cached in-process for the lifetime of
 * the service (ponytail: plain `Map`, no TTL/eviction — add one if
 * clusters get added/removed frequently at runtime).
 */
import {
  KubeConfig,
  CoreV1Api,
  AppsV1Api,
  NetworkingV1Api,
  VersionApi,
} from '@kubernetes/client-node';
import type {
  Cluster,
  Namespace,
  Workload,
  Pod,
  Service,
  Ingress,
  Deployment,
  StatefulSet,
  DaemonSet,
  NetworkPolicy,
} from '@aicc/models';
import type { Logger } from '@aicc/shared';
import {
  UnsupportedError,
  type KubernetesProvider,
  type ListOptions,
  type TestConnectionInput,
  type TestConnectionResult,
} from './registry.js';
import type { ClusterConnection, ClusterRepository } from '../repositories/cluster.repository.js';
import {
  mapNamespace,
  mapPod,
  mapService,
  mapIngress,
  mapDeployment,
  mapStatefulSet,
  mapDaemonSet,
  mapNetworkPolicy,
} from './k8s-mappers.js';

export interface K8sClients {
  core: CoreV1Api;
  apps: AppsV1Api;
  networking: NetworkingV1Api;
  version: VersionApi;
}

export type ClientFactory = (conn: ClusterConnection) => K8sClients;

export function defaultClientFactory(conn: ClusterConnection): K8sClients {
  const kc = new KubeConfig();
  kc.loadFromClusterAndUser(
    {
      name: 'aicc-cluster',
      server: conn.server,
      caData: conn.caBundle,
      skipTLSVerify: conn.insecureSkipVerify ?? false,
    },
    { name: 'aicc-user', token: conn.token },
  );
  return {
    core: kc.makeApiClient(CoreV1Api),
    apps: kc.makeApiClient(AppsV1Api),
    networking: kc.makeApiClient(NetworkingV1Api),
    version: kc.makeApiClient(VersionApi),
  };
}

export interface LiveProviderDeps {
  clusters: ClusterRepository;
  logger: Logger;
  clientFactory?: ClientFactory;
}

export class LiveProvider implements KubernetesProvider {
  readonly id = 'live';
  readonly name = 'Live Kubernetes API';
  readonly readOnly = true;

  private readonly clusters: ClusterRepository;
  private readonly logger: Logger;
  private readonly clientFactory: ClientFactory;
  private readonly cache = new Map<string, K8sClients>();

  constructor(deps: LiveProviderDeps) {
    this.clusters = deps.clusters;
    this.logger = deps.logger;
    this.clientFactory = deps.clientFactory ?? defaultClientFactory;
  }

  private async clientsFor(clusterId: string, tenantId: string): Promise<K8sClients> {
    // Tenant-scoped key: a cached client for one tenant's cluster must
    // never be served to another tenant, even with a colliding clusterId.
    const key = `${tenantId}:${clusterId}`;
    const cached = this.cache.get(key);
    if (cached) return cached;
    const conn = await this.clusters.getConnection(clusterId, tenantId);
    if (!conn) {
      throw new UnsupportedError(`cluster ${clusterId} has no live connection configured`);
    }
    const clients = this.clientFactory(conn);
    this.cache.set(key, clients);
    return clients;
  }

  private async clusterNameFor(clusterId: string, tenantId: string): Promise<string> {
    const cluster = await this.clusters.findById(clusterId, tenantId);
    if (!cluster) throw new UnsupportedError(`cluster ${clusterId} not found for tenant`);
    return cluster.name;
  }

  async testConnection(input: TestConnectionInput): Promise<TestConnectionResult> {
    const started = Date.now();
    try {
      const clients = this.clientFactory({
        server: input.server,
        token: input.token,
        caBundle: input.caBundle,
        insecureSkipVerify: input.insecureSkipVerify,
      });
      const info = await clients.version.getCode();
      return {
        ok: true,
        latencyMs: Date.now() - started,
        serverVersion: info.gitVersion,
        platform: info.platform,
      };
    } catch (err) {
      this.logger.debug({ err: (err as Error).message }, 'live provider connection test failed');
      return {
        ok: false,
        latencyMs: Date.now() - started,
        message: (err as Error).message ?? 'connection failed',
      };
    }
  }

  async listClusters(tenantId: string): Promise<Cluster[]> {
    const all = await this.clusters.list(tenantId);
    return all.filter((c) => (c.provider as string) !== 'fixture');
  }

  async listNamespaces(tenantId: string, clusterId: string): Promise<Namespace[]> {
    const [{ core }, clusterName] = await Promise.all([
      this.clientsFor(clusterId, tenantId),
      this.clusterNameFor(clusterId, tenantId),
    ]);
    const res = await core.listNamespace();
    return res.items.map((ns) => mapNamespace(tenantId, clusterId, clusterName, ns));
  }

  async listPods(tenantId: string, opts: ListOptions): Promise<Pod[]> {
    const [{ core }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await core.listNamespacedPod({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await core.listPodForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((pod) => mapPod(tenantId, opts.clusterId, clusterName, pod));
  }

  async listServices(tenantId: string, opts: ListOptions): Promise<Service[]> {
    const [{ core }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await core.listNamespacedService({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await core.listServiceForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((svc) => mapService(tenantId, opts.clusterId, clusterName, svc));
  }

  async listIngresses(tenantId: string, opts: ListOptions): Promise<Ingress[]> {
    const [{ networking }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await networking.listNamespacedIngress({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await networking.listIngressForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((ing) => mapIngress(tenantId, opts.clusterId, clusterName, ing));
  }

  async listDeployments(tenantId: string, opts: ListOptions): Promise<Deployment[]> {
    const [{ apps }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await apps.listNamespacedDeployment({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await apps.listDeploymentForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((dep) => mapDeployment(tenantId, opts.clusterId, clusterName, dep));
  }

  async listStatefulSets(tenantId: string, opts: ListOptions): Promise<StatefulSet[]> {
    const [{ apps }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await apps.listNamespacedStatefulSet({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await apps.listStatefulSetForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((sts) => mapStatefulSet(tenantId, opts.clusterId, clusterName, sts));
  }

  async listDaemonSets(tenantId: string, opts: ListOptions): Promise<DaemonSet[]> {
    const [{ apps }, clusterName] = await Promise.all([
      this.clientsFor(opts.clusterId, tenantId),
      this.clusterNameFor(opts.clusterId, tenantId),
    ]);
    const res = opts.namespace
      ? await apps.listNamespacedDaemonSet({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await apps.listDaemonSetForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((ds) => mapDaemonSet(tenantId, opts.clusterId, clusterName, ds));
  }

  async listWorkloads(tenantId: string, opts: ListOptions): Promise<Workload[]> {
    const [deployments, statefulSets, daemonSets] = await Promise.all([
      this.listDeployments(tenantId, opts),
      this.listStatefulSets(tenantId, opts),
      this.listDaemonSets(tenantId, opts),
    ]);
    return [...deployments, ...statefulSets, ...daemonSets];
  }

  async listNetworkPolicies(tenantId: string, opts: ListOptions): Promise<NetworkPolicy[]> {
    const { networking } = await this.clientsFor(opts.clusterId, tenantId);
    const res = opts.namespace
      ? await networking.listNamespacedNetworkPolicy({
          namespace: opts.namespace,
          labelSelector: opts.labelSelector,
        })
      : await networking.listNetworkPolicyForAllNamespaces({ labelSelector: opts.labelSelector });
    return res.items.map((np) => mapNetworkPolicy(tenantId, opts.clusterId, np));
  }
}
