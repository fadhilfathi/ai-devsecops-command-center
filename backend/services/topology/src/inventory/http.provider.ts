/**
 * HTTP Kubernetes provider — calls the kubernetes-service inventory
 * routes instead of the in-process fixture. Used when
 * `KUBERNETES_SERVICE_URL` is configured (see `.env.example`).
 *
 * Every response is validated against the `@aicc/models` Zod
 * schemas so a shape drift between services fails loudly instead of
 * shipping malformed data into the topology engine.
 */
import { signAccessToken, type JwtSecretOptions, type Logger } from '@aicc/shared';
import {
  ClusterListResponseSchema,
  NamespaceListResponseSchema,
  WorkloadListResponseSchema,
  PodListResponseSchema,
  ServiceListResponseSchema,
  IngressListResponseSchema,
  DeploymentListResponseSchema,
  StatefulSetListResponseSchema,
  DaemonSetListResponseSchema,
  NetworkPolicyListResponseSchema,
  type Cluster,
  type Namespace,
  type Workload,
  type Pod,
  type Service,
  type Ingress,
  type Deployment,
  type StatefulSet,
  type DaemonSet,
  type NetworkPolicy,
} from '@aicc/models';
import type {
  KubernetesProvider,
  ListOptions,
  TestConnectionInput,
  TestConnectionResult,
} from '../providers/kubernetes-provider.types.js';

export interface HttpProviderDeps {
  baseUrl: string;
  logger: Logger;
  /** Shared HS256 secret/issuer/audience — used to mint a short-lived
   * internal service token for this server-to-server call, since
   * kubernetes-service rejects unauthenticated requests. */
  auth: JwtSecretOptions;
}

function buildQuery(opts: Partial<ListOptions>): string {
  const params = new URLSearchParams();
  if (opts.clusterId) params.set('clusterId', opts.clusterId);
  if (opts.namespace) params.set('namespace', opts.namespace);
  if (opts.labelSelector) params.set('labelSelector', opts.labelSelector);
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

export function buildHttpKubernetesProvider(deps: HttpProviderDeps): KubernetesProvider {
  const { baseUrl, logger, auth } = deps;

  async function getJson(tenantId: string, path: string): Promise<unknown> {
    const url = `${baseUrl.replace(/\/$/, '')}${path}`;
    // ponytail: minted per-call (HMAC only, cheap) rather than cached —
    // revisit with a short-lived cache if this becomes hot.
    const token = signAccessToken(
      { sub: 'system:topology-service', role: 'platform_admin', tenantId },
      { ...auth, ttlSeconds: 60 },
    );
    const res = await fetch(url, {
      headers: { 'x-tenant-id': tenantId, authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      logger.error({ url, status: res.status }, 'kubernetes-service request failed');
      throw new Error(`kubernetes-service request failed: ${res.status} ${url}`);
    }
    return res.json();
  }

  return {
    id: 'http',
    name: 'Kubernetes Service (HTTP)',
    readOnly: true,
    async testConnection(_input: TestConnectionInput): Promise<TestConnectionResult> {
      return { ok: true, latencyMs: 0, message: 'not applicable for the HTTP provider' };
    },
    async listClusters(tenantId: string): Promise<Cluster[]> {
      const body = await getJson(tenantId, '/v1/kubernetes/clusters');
      return ClusterListResponseSchema.parse(body).items;
    },
    async listNamespaces(tenantId: string, clusterId: string): Promise<Namespace[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/namespaces${buildQuery({ clusterId })}`);
      return NamespaceListResponseSchema.parse(body).items;
    },
    async listWorkloads(tenantId: string, opts: ListOptions): Promise<Workload[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/workloads${buildQuery(opts)}`);
      return WorkloadListResponseSchema.parse(body).items;
    },
    async listPods(tenantId: string, opts: ListOptions): Promise<Pod[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/pods${buildQuery(opts)}`);
      return PodListResponseSchema.parse(body).items;
    },
    async listServices(tenantId: string, opts: ListOptions): Promise<Service[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/services${buildQuery(opts)}`);
      return ServiceListResponseSchema.parse(body).items;
    },
    async listIngresses(tenantId: string, opts: ListOptions): Promise<Ingress[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/ingresses${buildQuery(opts)}`);
      return IngressListResponseSchema.parse(body).items;
    },
    async listDeployments(tenantId: string, opts: ListOptions): Promise<Deployment[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/deployments${buildQuery(opts)}`);
      return DeploymentListResponseSchema.parse(body).items;
    },
    async listStatefulSets(tenantId: string, opts: ListOptions): Promise<StatefulSet[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/statefulsets${buildQuery(opts)}`);
      return StatefulSetListResponseSchema.parse(body).items;
    },
    async listDaemonSets(tenantId: string, opts: ListOptions): Promise<DaemonSet[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/daemonsets${buildQuery(opts)}`);
      return DaemonSetListResponseSchema.parse(body).items;
    },
    async listNetworkPolicies(tenantId: string, opts: ListOptions): Promise<NetworkPolicy[]> {
      const body = await getJson(tenantId, `/v1/kubernetes/network-policies${buildQuery(opts)}`);
      return NetworkPolicyListResponseSchema.parse(body).items;
    },
  };
}
