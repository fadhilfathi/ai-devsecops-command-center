/**
 * Compact fixture provider used by the reporting service. The
 * shape matches the kubernetes-service fixture; the data is
 * intentionally compact because the report engine only needs
 * a representative snapshot.
 */
import { randomUUID } from 'node:crypto';
import type { Logger } from '@aicc/shared';
import type {
  Cluster, ClusterProvider, ClusterPhase,
  Namespace, Pod, PodPhase, Container, Workload, WorkloadHealth,
  Service, ServiceType, Ingress, Deployment, StatefulSet, DaemonSet,
  DeploymentRolloutStatus, PodManagementPolicy, IngressClass,
} from '@aicc/models';
import type { KubernetesProvider, ListOptions, TestConnectionInput, TestConnectionResult } from './kubernetes-provider.types.js';

const NOW = (): string => new Date().toISOString();
const uuid = (): string => randomUUID();

function healthFromReplicas(ready: number, desired: number): WorkloadHealth {
  if (desired === 0) return 'unknown';
  if (ready === desired) return 'healthy';
  if (ready === 0) return 'unhealthy';
  return 'degraded';
}

function makeWorkload(args: {
  tenantId: string; clusterId: string; namespace: string;
  kind: 'deployment' | 'statefulset' | 'daemonset';
  name: string; image: string; imageDigest?: string;
  desired: number; ready: number; updated: number; available: number;
  resources: { cpuReq: number; cpuLim: number; memReq: number; memLim: number };
}): Workload {
  return {
    id: uuid(), tenantId: args.tenantId, clusterId: args.clusterId,
    clusterName: 'fixture', namespace: args.namespace,
    kind: args.kind, name: args.name, image: args.image, imageDigest: args.imageDigest,
    replicas: { desired: args.desired, ready: args.ready, updated: args.updated, available: args.available },
    health: healthFromReplicas(args.ready, args.desired),
    conditions: [{ type: 'Available', status: args.available >= args.desired ? 'true' : 'false', message: '', lastTransitionTime: NOW() }],
    labels: { app: args.name },
    resources: {
      cpuRequestsMillicores: args.resources.cpuReq, cpuLimitsMillicores: args.resources.cpuLim,
      memoryRequestsBytes: args.resources.memReq, memoryLimitsBytes: args.resources.memLim,
    },
    revision: '1', createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
  };
}

function makeClusters(tenantId: string): Cluster[] {
  return [{
    id: '11111111-1111-4111-8111-111111111111', tenantId, name: 'prod-us-east-1',
    server: 'https://api.prod-use1.example.com:6443',
    provider: 'eks' as ClusterProvider, k8sVersion: '1.29', region: 'us-east-1', environment: 'prod',
    phase: 'active' as ClusterPhase, nodeCount: 3, readyNodes: 3, totalCpuCores: 24,
    totalMemoryBytes: 96 * 1024 * 1024 * 1024,
    nodes: [
      { name: 'ip-10-0-2-10', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
      { name: 'ip-10-0-2-11', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
      { name: 'ip-10-0-2-12', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['disk_pressure'], unschedulable: false },
    ],
    labels: { env: 'prod' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
  }];
}

function makeNamespaces(tenantId: string, clusterId: string): Namespace[] {
  return [
    { id: uuid(), tenantId, clusterId, clusterName: 'prod-us-east-1', name: 'default', phase: 'active', workloadCount: 3, podCount: 6, runningPods: 5, pendingPods: 0, failedPods: 1, serviceCount: 2, restartsLast1h: 8, labels: {}, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
  ];
}

function makeDeployments(tenantId: string, opts: ListOptions): Deployment[] {
  return [
    {
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: opts.namespace ?? 'default',
        kind: 'deployment', name: 'payments-api',
        image: 'ghcr.io/example/payments-api:1.42.0',
        imageDigest: 'sha256:deadbeefcafe0000000000000000000000000000000000000000000000000000',
        desired: 3, ready: 3, updated: 3, available: 3,
        resources: { cpuReq: 250, cpuLim: 1000, memReq: 512 * 1024 * 1024, memLim: 1024 * 1024 * 1024 },
      }),
      strategy: 'rolling_update', rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'payments-api-7d4f8b', terminatingReplicas: 0,
      rollout: 'complete' as DeploymentRolloutStatus, paused: false,
    },
    {
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: opts.namespace ?? 'default',
        kind: 'deployment', name: 'legacy-batch',
        image: 'example/legacy-batch:1.0',
        desired: 2, ready: 2, updated: 2, available: 2,
        resources: { cpuReq: 2000, cpuLim: 4000, memReq: 8 * 1024 * 1024 * 1024, memLim: 16 * 1024 * 1024 * 1024 },
      }),
      strategy: 'recreate', rollingUpdate: {},
      currentReplicaSet: 'legacy-batch-1', terminatingReplicas: 0,
      rollout: 'complete' as DeploymentRolloutStatus, paused: false,
    },
  ];
}

function makeStatefulSets(_tenantId: string, opts: ListOptions): StatefulSet[] { return []; }
function makeDaemonSets(_tenantId: string, opts: ListOptions): DaemonSet[] { return []; }

function makePods(tenantId: string, opts: ListOptions): Pod[] {
  const c = (name: string, image: string, ready: boolean, restarts: number, term: 'crash_loop_back_off' | 'image_pull_back_off' | 'oom_killed' | 'unknown' = 'unknown'): Container => ({
    name, image, state: ready ? 'running' : 'waiting', ready, restartCount: restarts, lastTerminationReason: term,
    resources: { cpuRequestsMillicores: 250, cpuLimitsMillicores: 1000, memoryRequestsBytes: 256 * 1024 * 1024, memoryLimitsBytes: 512 * 1024 * 1024 },
    privileged: false, runAsRoot: false, addedCapabilities: [], hostPaths: [],
  });
  const phase = (n: number): PodPhase => (n % 5 === 0 ? 'pending' : n % 7 === 0 ? 'failed' : 'running');
  return [
    { id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture', namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd1', phase: phase(1), node: 'ip-10-0-2-10', podIp: '10.42.0.10', ownerKind: 'Deployment', ownerName: 'payments-api', serviceAccount: 'payments-api', containers: [c('app', 'ghcr.io/example/payments-api:1.42.0', true, 0, 'unknown')], conditions: [{ type: 'ready', status: 'true', lastTransitionTime: NOW() }], restarts: 0, startedAt: NOW(), lastTerminationReason: 'unknown', labels: { app: 'payments-api' }, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
    { id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture', namespace: opts.namespace ?? 'default', name: 'payments-api-7d4f8b-abcd2', phase: phase(0), ownerKind: 'Deployment', ownerName: 'payments-api', serviceAccount: 'default', containers: [c('app', 'ghcr.io/example/payments-api:1.42.0', false, 8, 'crash_loop_back_off')], conditions: [{ type: 'ready', status: 'false', message: 'containers with unready state: app', lastTransitionTime: NOW() }], restarts: 8, lastTerminationReason: 'crash_loop_back_off', labels: { app: 'payments-api' }, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
  ];
}

function makeServices(tenantId: string, opts: ListOptions): Service[] {
  return [{
    id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
    namespace: opts.namespace ?? 'default', name: 'payments-api',
    type: 'cluster_ip' as ServiceType, clusterIp: '10.96.0.10', externalIp: [],
    selector: { app: 'payments-api' },
    ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
    endpoints: [], fqdn: 'payments-api.default.svc.cluster.local',
    sessionAffinity: 'none', hasReadyEndpoints: true, ingressIds: [],
    labels: { app: 'payments-api' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
  }];
}

function makeIngresses(_tenantId: string, opts: ListOptions): Ingress[] {
  return [{
    id: uuid(), tenantId: _tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
    namespace: opts.namespace ?? 'default', name: 'public',
    className: 'nginx' as IngressClass,
    rules: [{ host: 'api.example.com', path: '/payments', pathType: 'Prefix', serviceName: 'payments-api', servicePort: 80 }],
    tls: [{ hosts: ['api.example.com'], secretName: 'api-tls' }],
    labels: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
  }];
}

export function buildFixtureProvider(_logger: Logger): KubernetesProvider {
  void _logger;
  return {
    id: 'fixture', name: 'Fixture (in-process)', readOnly: true,
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
    async listClusters(tenantId) { return makeClusters(tenantId); },
    async listNamespaces(tenantId, clusterId) { return makeNamespaces(tenantId, clusterId); },
    async listWorkloads(tenantId, opts) {
      return [...(await this.listDeployments(tenantId, opts)), ...(await this.listStatefulSets(tenantId, opts)), ...(await this.listDaemonSets(tenantId, opts))];
    },
    async listPods(tenantId, opts) { return makePods(tenantId, opts); },
    async listServices(tenantId, opts) { return makeServices(tenantId, opts); },
    async listIngresses(tenantId, opts) { return makeIngresses(tenantId, opts); },
    async listDeployments(tenantId, opts) { return makeDeployments(tenantId, opts); },
    async listStatefulSets(tenantId, opts) { return makeStatefulSets(tenantId, opts); },
    async listDaemonSets(tenantId, opts) { return makeDaemonSets(tenantId, opts); },
  };
}
