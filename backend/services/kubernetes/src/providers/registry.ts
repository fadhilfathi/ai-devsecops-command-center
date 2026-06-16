/**
 * Kubernetes provider abstraction.
 *
 * Sprint 4 ships two providers:
 *   - `fixture` — deterministic in-process data; the default for
 *     local dev and integration tests. No network access.
 *   - `live`    — placeholder that delegates to a future
 *     `@kubernetes/client-node` adapter (Sprint 5). For now it
 *     throws `UnsupportedError` so a misconfiguration fails fast
 *     with a useful message.
 *
 * A provider is responsible for translating between the
 * Kubernetes API server's representation and the AICC
 * `infrastructure/*` models. Handlers never see the raw API
 * objects.
 */
import { randomUUID } from 'node:crypto';
import {
  ClusterPhaseSchema,
  ClusterProviderSchema,
  type Cluster,
  type Namespace,
  type Workload,
  type WorkloadHealth,
  type Pod,
  type PodPhase,
  type Container,
  type Service,
  type ServiceType,
  type Ingress,
  type IngressClass,
  type IngressTls,
  type Deployment,
  type DeploymentRolloutStatus,
  type StatefulSet,
  type DaemonSet,
} from '@aicc/models';
import type { Logger } from '@aicc/shared';

export class UnsupportedError extends Error {
  readonly statusCode = 501;
  readonly code = 'PROVIDER_UNSUPPORTED';
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedError';
  }
}

export interface ProviderContext {
  logger: Logger;
}

export interface ListOptions {
  clusterId: string;
  namespace?: string;
  labelSelector?: string;
}

export interface KubernetesProvider {
  readonly id: string;
  readonly name: string;
  readonly readOnly: boolean;
  /** Quick connectivity check. Returns version + latency. */
  testConnection(input: TestConnectionInput): Promise<TestConnectionResult>;
  listClusters(tenantId: string): Promise<Cluster[]>;
  listNamespaces(tenantId: string, clusterId: string): Promise<Namespace[]>;
  listWorkloads(tenantId: string, opts: ListOptions): Promise<Workload[]>;
  listPods(tenantId: string, opts: ListOptions): Promise<Pod[]>;
  listServices(tenantId: string, opts: ListOptions): Promise<Service[]>;
  listIngresses(tenantId: string, opts: ListOptions): Promise<Ingress[]>;
  listDeployments(tenantId: string, opts: ListOptions): Promise<Deployment[]>;
  listStatefulSets(tenantId: string, opts: ListOptions): Promise<StatefulSet[]>;
  listDaemonSets(tenantId: string, opts: ListOptions): Promise<DaemonSet[]>;
}

export interface TestConnectionInput {
  server: string;
  token?: string;
  caBundle?: string;
  insecureSkipVerify?: boolean;
  name?: string;
}

export interface TestConnectionResult {
  ok: boolean;
  latencyMs: number;
  serverVersion?: string;
  platform?: string;
  message?: string;
}

class FixtureProvider implements KubernetesProvider {
  readonly id = 'fixture';
  readonly name = 'Fixture (in-process)';
  readonly readOnly = true;

  async testConnection(input: TestConnectionInput): Promise<TestConnectionResult> {
    // Validate the URL shape; the fixture "connects" instantly.
    const start = Date.now();
    try {
      const url = new URL(input.server);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        return {
          ok: false,
          latencyMs: 0,
          message: `unsupported protocol: ${url.protocol}`,
        };
      }
      return {
        ok: true,
        latencyMs: Date.now() - start,
        serverVersion: 'v1.29.4',
        platform: 'fixture',
        message: 'fixture provider accepted the connection',
      };
    } catch (err) {
      return {
        ok: false,
        latencyMs: 0,
        message: `invalid server URL: ${(err as Error).message}`,
      };
    }
  }

  async listClusters(tenantId: string): Promise<Cluster[]> {
    return buildFixtureClusters(tenantId);
  }
  async listNamespaces(tenantId: string, clusterId: string): Promise<Namespace[]> {
    return buildFixtureNamespaces(tenantId, clusterId);
  }
  async listWorkloads(tenantId: string, opts: ListOptions): Promise<Workload[]> {
    const [deps, sts, dss] = await Promise.all([
      this.listDeployments(tenantId, opts),
      this.listStatefulSets(tenantId, opts),
      this.listDaemonSets(tenantId, opts),
    ]);
    return [...deps, ...sts, ...dss];
  }
  async listPods(tenantId: string, opts: ListOptions): Promise<Pod[]> {
    return buildFixturePods(tenantId, opts);
  }
  async listServices(tenantId: string, opts: ListOptions): Promise<Service[]> {
    return buildFixtureServices(tenantId, opts);
  }
  async listIngresses(tenantId: string, opts: ListOptions): Promise<Ingress[]> {
    return buildFixtureIngresses(tenantId, opts);
  }
  async listDeployments(tenantId: string, opts: ListOptions): Promise<Deployment[]> {
    return buildFixtureDeployments(tenantId, opts);
  }
  async listStatefulSets(tenantId: string, opts: ListOptions): Promise<StatefulSet[]> {
    return buildFixtureStatefulSets(tenantId, opts);
  }
  async listDaemonSets(tenantId: string, opts: ListOptions): Promise<DaemonSet[]> {
    return buildFixtureDaemonSets(tenantId, opts);
  }
}

class LiveProvider implements KubernetesProvider {
  readonly id = 'live';
  readonly name = 'Live Kubernetes API';
  readonly readOnly = true;

  async testConnection(_input: TestConnectionInput): Promise<TestConnectionResult> {
    throw new UnsupportedError(
      'live kubernetes provider is wired in Sprint 5; configure a fixture provider for now',
    );
  }
  async listClusters(): Promise<Cluster[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listNamespaces(): Promise<Namespace[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listWorkloads(): Promise<Workload[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listPods(): Promise<Pod[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listServices(): Promise<Service[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listIngresses(): Promise<Ingress[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listDeployments(): Promise<Deployment[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listStatefulSets(): Promise<StatefulSet[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
  async listDaemonSets(): Promise<DaemonSet[]> {
    throw new UnsupportedError('live kubernetes provider is wired in Sprint 5');
  }
}

export interface ProviderRegistry {
  list(): KubernetesProvider[];
  get(id: string): KubernetesProvider | undefined;
  /** Default provider id, used when the request does not specify one. */
  defaultId(): string;
}

export function buildProviderRegistry(_ctx: ProviderContext): ProviderRegistry {
  const providers: KubernetesProvider[] = [new FixtureProvider(), new LiveProvider()];
  return {
    list() {
      return providers;
    },
    get(id) {
      return providers.find((p) => p.id === id);
    },
    defaultId() {
      return process.env.AICC_K8S_PROVIDER ?? 'fixture';
    },
  };
}

// -------------------------------------------------------------------------
// Fixture data builders — deterministic, hand-curated for the Sprint 4
// dashboard demos.
// -------------------------------------------------------------------------

const NOW = (): string => new Date().toISOString();

function uuid(): string {
  return randomUUID();
}

function healthFromReplicas(ready: number, desired: number): WorkloadHealth {
  if (desired === 0) return 'unknown';
  if (ready === desired) return 'healthy';
  if (ready === 0) return 'unhealthy';
  return 'degraded';
}

function makeWorkload(args: {
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  kind: 'deployment' | 'statefulset' | 'daemonset';
  name: string;
  image: string;
  desired: number;
  ready: number;
  updated: number;
  available: number;
  resources: { cpuReq: number; cpuLim: number; memReq: number; memLim: number };
}): Workload {
  return {
    id: uuid(),
    tenantId: args.tenantId,
    clusterId: args.clusterId,
    clusterName: args.clusterName,
    namespace: args.namespace,
    kind: args.kind,
    name: args.name,
    image: args.image,
    replicas: {
      desired: args.desired,
      ready: args.ready,
      updated: args.updated,
      available: args.available,
    },
    health: healthFromReplicas(args.ready, args.desired),
    conditions: [
      {
        type: 'Available',
        status: args.available >= args.desired ? 'true' : 'false',
        message: args.available >= args.desired ? 'Minimum replicas available' : 'Below desired replicas',
        lastTransitionTime: NOW(),
      },
    ],
    labels: { app: args.name, 'aicc.io/managed': 'true' },
    resources: {
      cpuRequestsMillicores: args.resources.cpuReq,
      cpuLimitsMillicores: args.resources.cpuLim,
      memoryRequestsBytes: args.resources.memReq,
      memoryLimitsBytes: args.resources.memLim,
    },
    revision: '1',
    uptimeSeconds: 60 * 60 * 24 * 3,
    createdAt: NOW(),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  };
}

function buildFixtureClusters(tenantId: string): Cluster[] {
  return [
    {
      id: '11111111-1111-4111-8111-111111111111',
      tenantId,
      name: 'prod-us-east-1',
      server: 'https://api.prod-use1.example.com:6443',
      provider: ClusterProviderSchema.parse('eks'),
      k8sVersion: '1.29',
      region: 'us-east-1',
      environment: 'prod',
      phase: ClusterPhaseSchema.parse('active'),
      nodeCount: 6,
      readyNodes: 6,
      totalCpuCores: 48,
      totalMemoryBytes: 192 * 1024 * 1024 * 1024,
      nodes: [
        { name: 'ip-10-0-1-10', roles: ['control-plane'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-10', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-11', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
      ],
      integrationId: undefined,
      labels: { env: 'prod', region: 'us-east-1' },
      createdAt: NOW(),
      updatedAt: NOW(),
      lastSyncedAt: NOW(),
    },
    {
      id: '22222222-2222-4222-8222-222222222222',
      tenantId,
      name: 'staging-eu-west-1',
      server: 'https://api.staging-euw1.example.com:6443',
      provider: ClusterProviderSchema.parse('gke'),
      k8sVersion: '1.28',
      region: 'europe-west1',
      environment: 'staging',
      phase: ClusterPhaseSchema.parse('active'),
      nodeCount: 3,
      readyNodes: 2,
      totalCpuCores: 12,
      totalMemoryBytes: 48 * 1024 * 1024 * 1024,
      nodes: [
        { name: 'gke-staging-pool-1', roles: ['worker'], kubeletVersion: 'v1.28.9', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'gke-staging-pool-2', roles: ['worker'], kubeletVersion: 'v1.28.9', architecture: 'amd64', conditions: ['disk_pressure'], unschedulable: false },
      ],
      integrationId: undefined,
      labels: { env: 'staging', region: 'eu-west-1' },
      createdAt: NOW(),
      updatedAt: NOW(),
      lastSyncedAt: NOW(),
    },
  ];
}

function buildFixtureNamespaces(tenantId: string, clusterId: string): Namespace[] {
  const clusters = buildFixtureClusters(tenantId);
  const cluster = clusters.find((c) => c.id === clusterId) ?? clusters[0]!;
  return [
    {
      id: uuid(), tenantId, clusterId, clusterName: cluster.name,
      name: 'default', phase: 'active',
      workloadCount: 4, podCount: 8, runningPods: 7, pendingPods: 0, failedPods: 1, serviceCount: 5,
      restartsLast1h: 12, labels: {}, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId, clusterName: cluster.name,
      name: 'kube-system', phase: 'active',
      workloadCount: 6, podCount: 12, runningPods: 12, pendingPods: 0, failedPods: 0, serviceCount: 4,
      restartsLast1h: 0, labels: {}, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId, clusterName: cluster.name,
      name: 'monitoring', phase: 'active',
      workloadCount: 3, podCount: 6, runningPods: 5, pendingPods: 1, failedPods: 0, serviceCount: 2,
      restartsLast1h: 3, labels: {}, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId, clusterName: cluster.name,
      name: 'aicc', phase: 'active',
      workloadCount: 2, podCount: 4, runningPods: 4, pendingPods: 0, failedPods: 0, serviceCount: 2,
      restartsLast1h: 0, labels: { 'aicc.io/managed': 'true' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function buildFixtureDeployments(tenantId: string, opts: ListOptions): Deployment[] {
  const base = makeWorkload({
    tenantId,
    clusterId: opts.clusterId,
    clusterName: 'cluster',
    namespace: opts.namespace ?? 'default',
    kind: 'deployment',
    name: 'payments-api',
    image: 'ghcr.io/example/payments-api:1.42.0',
    desired: 3,
    ready: 3,
    updated: 3,
    available: 3,
    resources: { cpuReq: 250, cpuLim: 1000, memReq: 512 * 1024 * 1024, memLim: 1024 * 1024 * 1024 },
  });
  const out: Deployment[] = [
    {
      ...base,
      strategy: 'rolling_update',
      rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'payments-api-7d4f8b',
      previousReplicaSet: 'payments-api-6c2a91',
      terminatingReplicas: 0,
      rollout: DeploymentRolloutStatusSchema.parse('complete'),
      changeCause: 'sprint-4 release',
      revisionHistoryLimit: 10,
      paused: false,
    },
  ];
  if (!opts.namespace || opts.namespace === 'monitoring') {
    out.push({
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
        namespace: 'monitoring', kind: 'deployment', name: 'prometheus',
        image: 'quay.io/prometheus/prometheus:v2.51.0',
        desired: 2, ready: 1, updated: 2, available: 1,
        resources: { cpuReq: 500, cpuLim: 2000, memReq: 1024 * 1024 * 1024, memLim: 4 * 1024 * 1024 * 1024 },
      }),
      strategy: 'rolling_update',
      rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'prometheus-9a1',
      terminatingReplicas: 1,
      rollout: DeploymentRolloutStatusSchema.parse('progressing'),
      paused: false,
    });
  }
  return out;
}

function buildFixtureStatefulSets(_tenantId: string, opts: ListOptions): StatefulSet[] {
  return [
    {
      ...makeWorkload({
        tenantId: _tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
        namespace: opts.namespace ?? 'default', kind: 'statefulset', name: 'postgres',
        image: 'postgres:16.2',
        desired: 1, ready: 1, updated: 1, available: 1,
        resources: { cpuReq: 1000, cpuLim: 2000, memReq: 2 * 1024 * 1024 * 1024, memLim: 4 * 1024 * 1024 * 1024 },
      }),
      serviceName: 'postgres-hl',
      podManagementPolicy: 'ordered_ready',
      updateStrategy: 'rolling_update',
      volumeClaimTemplates: [
        { name: 'data', storageClassName: 'gp3', sizeBytes: 100 * 1024 * 1024 * 1024 },
      ],
      currentRevision: 'postgres-7d4f8b',
      updateRevision: 'postgres-7d4f8b',
    },
  ];
}

function buildFixtureDaemonSets(_tenantId: string, opts: ListOptions): DaemonSet[] {
  return [
    {
      ...makeWorkload({
        tenantId: _tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
        namespace: opts.namespace ?? 'kube-system', kind: 'daemonset', name: 'fluentbit',
        image: 'fluent/fluent-bit:2.2',
        desired: 3, ready: 3, updated: 3, available: 3,
        resources: { cpuReq: 50, cpuLim: 200, memReq: 64 * 1024 * 1024, memLim: 256 * 1024 * 1024 },
      }),
      updateStrategy: 'rolling_update',
      desiredNumberScheduled: 3,
      currentNumberScheduled: 3,
      numberReady: 3,
      numberMisscheduled: 0,
    },
  ];
}

function buildFixturePods(tenantId: string, opts: ListOptions): Pod[] {
  const containers = (name: string, image: string, ready: boolean, restarts: number): Container[] => [
    {
      name,
      image,
      state: ready ? 'running' : 'waiting',
      ready,
      restartCount: restarts,
      lastTerminationReason: restarts > 5 ? 'crash_loop_back_off' : 'unknown',
      resources: { cpuRequestsMillicores: 250, cpuLimitsMillicores: 1000, memoryRequestsBytes: 256 * 1024 * 1024, memoryLimitsBytes: 512 * 1024 * 1024 },
      privileged: false,
      runAsRoot: false,
      addedCapabilities: [],
      hostPaths: [],
    },
  ];
  const phase = (n: number): PodPhase => (n % 5 === 0 ? 'pending' : n % 7 === 0 ? 'failed' : 'running');
  return [
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd1',
      phase: phase(1), node: 'ip-10-0-2-10', podIp: '10.42.0.10',
      ownerKind: 'Deployment', ownerName: 'payments-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/payments-api:1.42.0', true, 0),
      conditions: [{ type: 'ready', status: 'true', lastTransitionTime: NOW() }],
      restarts: 0, startedAt: NOW(),
      lastTerminationReason: 'unknown',
      labels: { app: 'payments-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd2',
      phase: phase(0), node: undefined, podIp: undefined,
      ownerKind: 'Deployment', ownerName: 'payments-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/payments-api:1.42.0', false, 8),
      conditions: [{ type: 'ready', status: 'false', message: 'containers with unready state: app', lastTransitionTime: NOW() }],
      restarts: 8, lastTerminationReason: 'crash_loop_back_off',
      labels: { app: 'payments-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'orders-api-9aa-efef',
      phase: phase(3), node: 'ip-10-0-2-11', podIp: '10.42.1.5',
      ownerKind: 'Deployment', ownerName: 'orders-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/orders-api:2.1.0', true, 2),
      conditions: [{ type: 'ready', status: 'true', lastTransitionTime: NOW() }],
      restarts: 2, startedAt: NOW(), lastTerminationReason: 'oom_killed',
      labels: { app: 'orders-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function buildFixtureServices(tenantId: string, opts: ListOptions): Service[] {
  return [
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'payments-api',
      type: 'cluster_ip' as ServiceType,
      clusterIp: '10.96.0.10',
      externalIp: [],
      selector: { app: 'payments-api' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [
        { podName: 'payments-api-7d4f8b-abcd1', podIp: '10.42.0.10', nodeName: 'ip-10-0-2-10', ready: true },
      ],
      fqdn: `payments-api.${opts.namespace ?? 'default'}.svc.cluster.local`,
      sessionAffinity: 'none',
      hasReadyEndpoints: true,
      ingressIds: [],
      labels: { app: 'payments-api' },
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'orders-api',
      type: 'cluster_ip' as ServiceType,
      clusterIp: '10.96.0.11',
      externalIp: [],
      selector: { app: 'orders-api' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [
        { podName: 'orders-api-9aa-efef', podIp: '10.42.1.5', nodeName: 'ip-10-0-2-11', ready: true },
      ],
      fqdn: `orders-api.${opts.namespace ?? 'default'}.svc.cluster.local`,
      sessionAffinity: 'none',
      hasReadyEndpoints: true,
      ingressIds: [],
      labels: { app: 'orders-api' },
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function buildFixtureIngresses(tenantId: string, opts: ListOptions): Ingress[] {
  return [
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'cluster',
      namespace: opts.namespace ?? 'default', name: 'public',
      className: 'nginx' as IngressClass,
      rules: [
        { host: 'api.example.com', path: '/payments', pathType: 'Prefix', serviceName: 'payments-api', servicePort: 80 },
        { host: 'api.example.com', path: '/orders', pathType: 'Prefix', serviceName: 'orders-api', servicePort: 80 },
      ],
      tls: [{ hosts: ['api.example.com'], secretName: 'api-tls' }] as IngressTls[],
      defaultBackend: undefined,
      labels: { 'aicc.io/managed': 'true' },
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}
