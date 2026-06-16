/**
 * Fixture provider for the topology service.
 *
 * The topology service needs a slightly richer deployment /
 * ingress mix than the other services, so the fixture data
 * below includes two services (payments-api, orders-api),
 * one ingress that routes to both, and an orders-api service
 * that calls the payments-api service (used to render an
 * inter-service edge in the Application Graph).
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
  return [
    {
      id: '11111111-1111-4111-8111-111111111111', tenantId, name: 'prod-us-east-1',
      server: 'https://api.prod-use1.example.com:6443',
      provider: 'eks' as ClusterProvider, k8sVersion: '1.29', region: 'us-east-1', environment: 'prod',
      phase: 'active' as ClusterPhase, nodeCount: 3, readyNodes: 3, totalCpuCores: 24,
      totalMemoryBytes: 96 * 1024 * 1024 * 1024,
      nodes: [
        { name: 'ip-10-0-2-10', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-11', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
        { name: 'ip-10-0-2-12', roles: ['worker'], kubeletVersion: 'v1.29.4', architecture: 'amd64', conditions: ['ready'], unschedulable: false },
      ],
      labels: { env: 'prod' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    },
  ];
}

function makeNamespaces(tenantId: string, clusterId: string): Namespace[] {
  return [
    { id: uuid(), tenantId, clusterId, clusterName: 'prod-us-east-1', name: 'default', phase: 'active', workloadCount: 2, podCount: 4, runningPods: 4, pendingPods: 0, failedPods: 0, serviceCount: 2, restartsLast1h: 0, labels: {}, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
    { id: uuid(), tenantId, clusterId, clusterName: 'prod-us-east-1', name: 'platform', phase: 'active', workloadCount: 1, podCount: 2, runningPods: 2, pendingPods: 0, failedPods: 0, serviceCount: 1, restartsLast1h: 0, labels: {}, annotations: {}, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW() },
  ];
}

function makeDeployments(tenantId: string, opts: ListOptions): Deployment[] {
  const ns = opts.namespace ?? 'default';
  const arr: Deployment[] = [];
  if (ns === 'default') {
    arr.push({
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: ns,
        kind: 'deployment', name: 'payments-api',
        image: 'ghcr.io/example/payments-api:1.42.0',
        imageDigest: 'sha256:deadbeefcafe0000000000000000000000000000000000000000000000000000',
        desired: 3, ready: 3, updated: 3, available: 3,
        resources: { cpuReq: 250, cpuLim: 1000, memReq: 512 * 1024 * 1024, memLim: 1024 * 1024 * 1024 },
      }),
      strategy: 'rolling_update', rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'payments-api-7d4f8b', terminatingReplicas: 0,
      rollout: 'complete' as DeploymentRolloutStatus, paused: false,
    });
    arr.push({
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: ns,
        kind: 'deployment', name: 'orders-api',
        image: 'ghcr.io/example/orders-api:2.1.0',
        imageDigest: 'sha256:cafebabedeadbeef000000000000000000000000000000000000000000000000',
        desired: 2, ready: 2, updated: 2, available: 2,
        resources: { cpuReq: 200, cpuLim: 800, memReq: 256 * 1024 * 1024, memLim: 512 * 1024 * 1024 },
      }),
      strategy: 'rolling_update', rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'orders-api-9a1', terminatingReplicas: 0,
      rollout: 'complete' as DeploymentRolloutStatus, paused: false,
    });
  }
  if (ns === 'platform') {
    arr.push({
      ...makeWorkload({
        tenantId, clusterId: opts.clusterId, namespace: ns,
        kind: 'deployment', name: 'auth-service',
        image: 'ghcr.io/example/auth-service:3.0.0',
        imageDigest: 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        desired: 2, ready: 2, updated: 2, available: 2,
        resources: { cpuReq: 300, cpuLim: 1000, memReq: 256 * 1024 * 1024, memLim: 512 * 1024 * 1024 },
      }),
      strategy: 'rolling_update', rollingUpdate: { maxSurge: 1, maxUnavailable: 0 },
      currentReplicaSet: 'auth-service-1', terminatingReplicas: 0,
      rollout: 'complete' as DeploymentRolloutStatus, paused: false,
    });
  }
  return arr;
}

function makeStatefulSets(_tenantId: string, opts: ListOptions): StatefulSet[] { return []; }
function makeDaemonSets(_tenantId: string, opts: ListOptions): DaemonSet[] { return []; }
function makePods(_tenantId: string, opts: ListOptions): Pod[] { return []; }

function makeServices(tenantId: string, opts: ListOptions): Service[] {
  const ns = opts.namespace ?? 'default';
  const arr: Service[] = [];
  if (ns === 'default') {
    arr.push({
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: ns, name: 'payments-api',
      type: 'cluster_ip' as ServiceType, clusterIp: '10.96.0.10', externalIp: [],
      selector: { app: 'payments-api' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [], fqdn: `payments-api.${ns}.svc.cluster.local`,
      sessionAffinity: 'none', hasReadyEndpoints: true, ingressIds: [],
      labels: { app: 'payments-api' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    });
    arr.push({
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: ns, name: 'orders-api',
      type: 'cluster_ip' as ServiceType, clusterIp: '10.96.0.11', externalIp: [],
      selector: { app: 'orders-api' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [], fqdn: `orders-api.${ns}.svc.cluster.local`,
      sessionAffinity: 'none', hasReadyEndpoints: true, ingressIds: [],
      labels: { app: 'orders-api' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    });
  }
  if (ns === 'platform') {
    arr.push({
      id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
      namespace: ns, name: 'auth-service',
      type: 'cluster_ip' as ServiceType, clusterIp: '10.96.1.10', externalIp: [],
      selector: { app: 'auth-service' },
      ports: [{ name: 'http', protocol: 'TCP', port: 80, targetPort: 8080 }],
      endpoints: [], fqdn: `auth-service.${ns}.svc.cluster.local`,
      sessionAffinity: 'none', hasReadyEndpoints: true, ingressIds: [],
      labels: { app: 'auth-service' }, createdAt: NOW(), updatedAt: NOW(), lastSyncedAt: NOW(),
    });
  }
  return arr;
}

function makeIngresses(tenantId: string, opts: ListOptions): Ingress[] {
  if ((opts.namespace ?? 'default') !== 'default') return [];
  return [{
    id: uuid(), tenantId, clusterId: opts.clusterId, clusterName: 'fixture',
    namespace: 'default', name: 'public',
    className: 'nginx' as IngressClass,
    rules: [
      { host: 'api.example.com', path: '/payments', pathType: 'Prefix', serviceName: 'payments-api', servicePort: 80 },
      { host: 'api.example.com', path: '/orders', pathType: 'Prefix', serviceName: 'orders-api', servicePort: 80 },
    ],
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
