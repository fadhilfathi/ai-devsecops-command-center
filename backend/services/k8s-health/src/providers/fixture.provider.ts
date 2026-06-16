/**
 * Fixture provider — deterministic in-process Kubernetes data
 * shared by the k8s-health, runtime-security, inventory, cost,
 * and topology services in Sprint 4.
 *
 * The shape is identical to the kubernetes-service fixture
 * provider, but the data is generated locally so each consumer
 * service can be developed in isolation.
 */
import { randomUUID } from 'node:crypto';
import type { Logger } from '@aicc/shared';
import type {
  Cluster,
  ClusterProvider,
  ClusterPhase,
  Namespace,
  Pod,
  PodPhase,
  Container,
  Workload,
  WorkloadHealth,
  Service,
  Ingress,
  Deployment,
  StatefulSet,
  DaemonSet,
  DeploymentRolloutStatus,
  PodManagementPolicy,
  ServiceType,
  IngressClass,
} from '@aicc/models';
import type {
  KubernetesProvider,
  ListOptions,
  TestConnectionInput,
  TestConnectionResult,
} from './kubernetes-provider.types.js';

const NOW = (): string => new Date().toISOString();
const uuid = (): string => randomUUID();

function healthFromReplicas(ready: number, desired: number): WorkloadHealth {
  if (desired === 0) return 'unknown';
  if (ready === desired) return 'healthy';
  if (ready === 0) return 'unhealthy';
  return 'degraded';
}

function makeWorkload(args: {
  tenantId: string;
  clusterId: string;
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
    clusterName: 'fixture',
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
    labels: { app: args.name },
    resources: {
      cpuRequestsMillicores: args.resources.cpuReq,
      cpuLimitsMillicores: args.resources.cpuLim,
      memoryRequestsBytes: args.resources.memReq,
      memoryLimitsBytes: args.resources.memLim,
    },
    revision: '1',
    uptimeSeconds: 86400,
    createdAt: NOW(),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  };
}

function makeClusters(tenantId: string): Cluster[] {
  return [
    {
      id: '11111111-1111-4111-8111-111111111111',
      tenantId,
      name: 'prod-us-east-1',
      server: 'https://api.prod-use1.example.com:6443',
      provider: 'eks' as ClusterProvider,
      k8sVersion: '1.29',
      region: 'us-east-1',
      environment: 'prod',
      phase: 'active' as ClusterPhase,
      nodeCount: 3,
      readyNodes: 3,
      totalCpuCores: 24,
      totalMemoryBytes: 96 * 1024 * 1024 * 1024,
      nodes: [
        { name: 'ip-10-0-2-10', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-11', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-12', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['disk_pressure'], unschedulable: false },
      ],
      labels: { env: 'prod' },
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function makeNamespaces(tenantId: string, clusterId: string): Namespace[] {
  return [
    { id: uuid(), tenantId, clusterId, clusterName: 'prod-us-east-1', name: 'default', phase: 'active', workloadCount: 3, podCount: 6, runningPods: 4, pendingPods: 1, failedPods: 1, serviceCount: 4, restartsLast1h: 14, labels: {}, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
    { id: uuid(), tenantId, clusterId, clusterName: 'prod-us-east-1', name: 'kube-system', phase: 'active', workloadCount: 4, podCount: 8, runningPods: 8, pendingPods: 0, failedPods: 0, serviceCount: 3, restartsLast1h: 0, labels: {}, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
  ];
}

function makeDeployments(tenantId: string, opts: ListOptions): Deployment[] {
  return [
    {
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: opts.namespace ?? 'default',
        kind: 'deployment', name: 'payments-api',
        image: 'ghcr.io/example/payments-api:1.42.0',
        desired: 3, ready: 2, updated: 3, available: 2,
        resources: { cpuReq: 250, cpuLim: 1000, memReq: 512 * 1024 * 1024, memLim: 1024 * 1024 * 1024 },
      }),
      strategy: 'rolling_update',
      rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'payments-api-7d4f8b',
      terminatingReplicas: 1,
      rollout: 'progressing' as DeploymentRolloutStatus,
      paused: false,
    },
  ];
}

function makeStatefulSets(tenantId: string, opts: ListOptions): StatefulSet[] {
  return [
    {
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: opts.namespace ?? 'default',
        kind: 'statefulset', name: 'postgres',
        image: 'postgres:16.2',
        desired: 1, ready: 1, updated: 1, available: 1,
        resources: { cpuReq: 1000, cpuLim: 2000, memReq: 2 * 1024 * 1024 * 1024, memLim: 4 * 1024 * 1024 * 1024 },
      }),
      serviceName: 'postgres-hl',
      podManagementPolicy: 'ordered_ready' as PodManagementPolicy,
      updateStrategy: 'rolling_update',
      volumeClaimTemplates: [
        { name: 'data', storageClassName: 'gp3', sizeBytes: 100 * 1024 * 1024 * 1024, accessModes: ['ReadWriteOnce'] },
      ],
      currentRevision: 'postgres-7d4f8b',
      updateRevision: 'postgres-7d4f8b',
    },
  ];
}

function makeDaemonSets(tenantId: string, opts: ListOptions): DaemonSet[] {
  return [
    {
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: opts.namespace ?? 'kube-system',
        kind: 'daemonset', name: 'fluentbit',
        image: 'fluent/fluent-bit:2.2',
        desired: 3, ready: 2, updated: 3, available: 2,
        resources: { cpuReq: 50, cpuLim: 200, memReq: 64 * 1024 * 1024, memLim: 256 * 1024 * 1024 },
      }),
      updateStrategy: 'rolling_update',
      desiredNumberScheduled: 3,
      currentNumberScheduled: 3,
      numberReady: 2,
      numberMisscheduled: 0,
    },
  ];
}

function makePods(tenantId: string, opts: ListOptions): Pod[] {
  const containers = (name: string, image: string, ready: boolean, restarts: number, term: 'crash_loop_back_off' | 'image_pull_back_off' | 'oom_killed' | 'unknown' = 'unknown'): Container[] => [
    {
      name,
      image,
      state: ready ? 'running' : 'waiting',
      ready,
      restartCount: restarts,
      lastTerminationReason: term,
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
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd1',
      phase: phase(1), node: 'ip-10-0-2-10', podIp: '10.42.0.10',
      ownerKind: 'Deployment', ownerName: 'payments-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/payments-api:1.42.0', true, 0, 'unknown'),
      conditions: [{ type: 'ready', status: 'true', lastTransitionTime: NOW() }],
      restarts: 0, startedAt: NOW(), lastTerminationReason: 'unknown',
      labels: { app: 'payments-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd2',
      phase: phase(0), node: undefined, podIp: undefined,
      ownerKind: 'Deployment', ownerName: 'payments-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/payments-api:1.42.0', false, 8, 'crash_loop_back_off'),
      conditions: [{ type: 'ready', status: 'false', message: 'containers with unready state: app', lastTransitionTime: NOW() }],
      restarts: 8, lastTerminationReason: 'crash_loop_back_off',
      labels: { app: 'payments-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: opts.namespace ?? 'default', name: 'orders-api-9aa-efef',
      phase: phase(3), node: 'ip-10-0-2-11', podIp: '10.42.1.5',
      ownerKind: 'Deployment', ownerName: 'orders-api',
      serviceAccount: 'default',
      containers: containers('app', 'ghcr.io/example/orders-api:2.1.0', true, 2, 'oom_killed'),
      conditions: [{ type: 'ready', status: 'true', lastTransitionTime: NOW() }],
      restarts: 2, startedAt: NOW(), lastTerminationReason: 'oom_killed',
      labels: { app: 'orders-api' }, annotations: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function makeServices(tenantId: string, opts: ListOptions): Service[] {
  return [
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: opts.namespace ?? 'default', name: 'payments-api',
      type: 'cluster_ip' as ServiceType,
      clusterIp: '10.96.0.10', externalIp: [],
      selector: { app: 'payments-api' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [{ podName: 'payments-api-7d4f8b-abcd1', podIp: '10.42.0.10', nodeName: 'ip-10-0-2-10', ready: true }],
      fqdn: `payments-api.${opts.namespace ?? 'default'}.svc.cluster.local`,
      sessionAffinity: 'none', hasReadyEndpoints: true, ingressIds: [],
      labels: { app: 'payments-api' },
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function makeIngresses(tenantId: string, opts: ListOptions): Ingress[] {
  return [
    {
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: opts.namespace ?? 'default', name: 'public',
      className: 'nginx' as IngressClass,
      rules: [{ host: 'api.example.com', path: '/payments', pathType: 'Prefix', serviceName: 'payments-api', servicePort: 80 }],
      tls: [{ hosts: ['api.example.com'], secretName: 'api-tls' }],
      labels: {},
      createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

export function buildFixtureProvider(_logger: Logger): KubernetesProvider {
  void _logger;
  return {
    id: 'fixture',
    name: 'Fixture (in-process)',
    readOnly: true,
    async testConnection(input: TestConnectionInput): Promise<TestConnectionResult> {
      const start = Date.now();
      try {
        const url = new URL(input.server);
        if (url.protocol !== 'https:' && url.protocol !== 'http:') {
          return { ok: false, latencyMs: 0, message: `unsupported protocol: ${url.protocol}` };
        }
        return { ok: true, latencyMs: Date.now() - start, serverVersion: 'v1.29.4', platform: 'fixture' };
      } catch (err) {
        return { ok: false, latencyMs: 0, message: `invalid server URL: ${(err as Error).message}` };
      }
    },
    async listClusters(tenantId) {
      return makeClusters(tenantId);
    },
    async listNamespaces(tenantId, clusterId) {
      return makeNamespaces(tenantId, clusterId);
    },
    async listWorkloads(tenantId, opts) {
      return [...(await this.listDeployments(tenantId, opts)), ...(await this.listStatefulSets(tenantId, opts)), ...(await this.listDaemonSets(tenantId, opts))];
    },
    async listPods(tenantId, opts) {
      return makePods(tenantId, opts);
    },
    async listServices(tenantId, opts) {
      return makeServices(tenantId, opts);
    },
    async listIngresses(tenantId, opts) {
      return makeIngresses(tenantId, opts);
    },
    async listDeployments(tenantId, opts) {
      return makeDeployments(tenantId, opts);
    },
    async listStatefulSets(tenantId, opts) {
      return makeStatefulSets(tenantId, opts);
    },
    async listDaemonSets(tenantId, opts) {
      return makeDaemonSets(tenantId, opts);
    },
  };
}
