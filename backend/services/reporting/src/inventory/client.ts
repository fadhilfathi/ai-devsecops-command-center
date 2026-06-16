/**
 * Reporting inventory client.
 *
 * In Sprint 4 the reporting service uses the in-process fixture
 * provider; the Sprint 5 wiring will hit the k8s-health,
 * runtime-security, cost-intelligence, and topology services
 * over HTTP when their URLs are set.
 */
import type { Logger } from '@aicc/shared';
import type {
  Cluster, Namespace, Workload, Pod, Service, Deployment, StatefulSet, DaemonSet, Ingress,
  InfrastructureHealth, RuntimeSecurityReport, CostAnalysis, TopologyGraph,
} from '@aicc/models';
import { buildFixtureProvider, type KubernetesProvider, type ListOptions } from '../providers/index.js';

export interface ReportData {
  clusters: Cluster[];
  namespaces: Namespace[];
  workloads: Workload[];
  pods: Pod[];
  services: Service[];
  deployments: Deployment[];
  statefulsets: StatefulSet[];
  daemonsets: DaemonSet[];
  ingresses: Ingress[];
  health: InfrastructureHealth[];
  runtimeReport: RuntimeSecurityReport | undefined;
  costAnalysis: CostAnalysis | undefined;
  topology: TopologyGraph | undefined;
}

export interface InventoryClient {
  fetch(tenantId: string, clusterId?: string): Promise<ReportData>;
}

/** Tiny synthetic health builder — used when the k8s-health
 * service is not wired yet. */
function buildSyntheticHealth(tenantId: string, clusters: Cluster[], pods: Pod[]): InfrastructureHealth[] {
  return clusters.map((c) => {
    const clusterPods = pods.filter((p) => p.clusterId === c.id);
    const crashed = clusterPods.filter((p) => p.lastTerminationReason === 'crash_loop_back_off').length;
    const oom = clusterPods.filter((p) => p.lastTerminationReason === 'oom_killed').length;
    const pending = clusterPods.filter((p) => p.phase === 'pending').length;
    const pressure = c.nodes.filter((n) => n.conditions.some((x) => x !== 'ready')).length;
    const counts = { critical: crashed, high: oom + pressure, medium: pending, low: 0, info: 0 };
    const score = Math.max(0, 100 - 8 * counts.critical - 4 * counts.high - 2 * counts.medium);
    return {
      id: `synth-${c.id}`, tenantId, scope: 'cluster' as const,
      subject: { kind: 'Cluster', name: c.name, clusterId: c.id },
      score: {
        score, band: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F',
        status: score >= 90 ? 'healthy' : score >= 70 ? 'degraded' : 'unhealthy',
        counts, generatedAt: new Date().toISOString(),
      },
      issues: [],
      recommendations: [],
      generatedAt: new Date().toISOString(),
    };
  });
}

function buildSyntheticRuntime(tenantId: string, clusters: Cluster[], pods: Pod[]): RuntimeSecurityReport | undefined {
  if (clusters.length === 0) return undefined;
  const cluster = clusters[0]!;
  const findings = pods.filter((p) => p.clusterId === cluster.id && p.lastTerminationReason !== 'unknown').map((p) => ({
    id: p.id, tenantId, clusterId: cluster.id, clusterName: cluster.name, namespace: p.namespace,
    subject: 'pod' as const, subjectKind: 'Pod', subjectName: p.name,
    ruleId: 'AICC-RT-OBS', ruleName: 'Observed termination',
    category: 'unsafe_security_context' as const,
    level: p.lastTerminationReason === 'crash_loop_back_off' ? 'critical' as const : 'high' as const,
    severity: p.lastTerminationReason === 'crash_loop_back_off' ? 'critical' as const : 'high' as const,
    message: `Pod ${p.name} last termination: ${p.lastTerminationReason}`,
    evidencePath: 'pod.status.containerStatuses[*].state.terminated.reason',
    evidenceValue: p.lastTerminationReason,
    remediation: 'Inspect pod logs and event stream',
    references: [], detectedAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }));
  return {
    id: `rr-synth-${cluster.id}`, tenantId, clusterId: cluster.id,
    windowStart: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    windowEnd: new Date().toISOString(),
    riskLevel: findings.some((f) => f.level === 'critical') ? 'critical' : findings.length > 0 ? 'high' : 'low',
    score: Math.max(0, 100 - 8 * findings.filter((f) => f.level === 'critical').length - 4 * findings.filter((f) => f.level === 'high').length),
    counts: { critical: findings.filter((f) => f.level === 'critical').length, high: findings.filter((f) => f.level === 'high').length, medium: 0, low: 0 },
    categoryCounts: { unsafe_security_context: findings.length },
    findings,
    recommendations: findings.length > 0 ? [{ id: 'rec-synth-1', title: 'Investigate recent terminations', detail: 'Restart the affected workloads after inspecting logs.', level: 'high' as const, affectedCount: findings.length }] : [],
    generatedAt: new Date().toISOString(),
  };
}

function buildSyntheticCost(tenantId: string, cluster: Cluster, workloads: Workload[]): CostAnalysis | undefined {
  if (!cluster) return undefined;
  const monthly = workloads.reduce((acc, w) => {
    const cpu = (w.resources.cpuRequestsMillicores / 1000) * 0.041 * 24 * 30;
    const mem = (w.resources.memoryRequestsBytes / (1024 ** 3)) * 0.005 * 24 * 30;
    return acc + cpu + mem;
  }, 0);
  return {
    id: 'ca-synth-1', tenantId, clusterId: cluster.id,
    windowStart: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    windowEnd: new Date().toISOString(),
    pricing: { cpuUsdPerHour: 0.041, memoryUsdPerHour: 0.005, gpuUsdPerHour: 2.5, networkEgressUsdPerHour: 0, currency: 'USD' },
    currentMonthlyUsd: Math.round(monthly),
    recommendedMonthlyUsd: Math.round(monthly * 0.6),
    potentialMonthlySavingsUsd: Math.round(monthly * 0.4),
    workloads: workloads.map((w) => ({
      workloadId: w.id, workloadName: w.name, namespace: w.namespace, kind: w.kind,
      currentMonthlyUsd: Math.round((w.resources.cpuRequestsMillicores / 1000) * 0.041 * 24 * 30 + (w.resources.memoryRequestsBytes / (1024 ** 3)) * 0.005 * 24 * 30),
      recommendedMonthlyUsd: Math.round(((w.resources.cpuRequestsMillicores / 1000) * 0.041 * 24 * 30 + (w.resources.memoryRequestsBytes / (1024 ** 3)) * 0.005 * 24 * 30) * 0.6),
      potentialMonthlySavingsUsd: Math.round(((w.resources.cpuRequestsMillicores / 1000) * 0.041 * 24 * 30 + (w.resources.memoryRequestsBytes / (1024 ** 3)) * 0.005 * 24 * 30) * 0.4),
      utilisation: { cpuP50: 0.4, cpuP95: 0.6, memoryP50: 0.5, memoryP95: 0.7 },
      requests: { cpuMillicores: w.resources.cpuRequestsMillicores, memoryBytes: w.resources.memoryRequestsBytes },
      limits: { cpuMillicores: w.resources.cpuLimitsMillicores, memoryBytes: w.resources.memoryLimitsBytes },
    })),
    findings: [], recommendations: [],
    generatedAt: new Date().toISOString(),
  };
}

function buildSyntheticTopology(tenantId: string, cluster: Cluster, workloads: Workload[], services: Service[], ingresses: Ingress[]): TopologyGraph {
  const nodes = [
    ...ingresses.map((i) => ({ id: i.id, label: i.name, kind: 'ingress' as const, namespace: i.namespace, clusterId: i.clusterId, clusterName: i.clusterName, tags: [`class=${i.className}`], metadata: {} })),
    ...services.map((s) => ({ id: s.id, label: s.name, kind: 'service' as const, namespace: s.namespace, clusterId: s.clusterId, clusterName: s.clusterName, tags: Object.entries(s.selector).map(([k, v]) => `${k}=${v}`), metadata: {} })),
    ...workloads.map((w) => ({ id: w.id, label: w.name, kind: 'workload' as const, namespace: w.namespace, clusterId: w.clusterId, clusterName: w.clusterName, tags: [`kind=${w.kind}`], metadata: {} })),
  ];
  const edges: Array<{ id: string; source: string; target: string; kind: 'routes_to' | 'selects'; weight: number; label?: string; metadata: Record<string, unknown> }> = [];
  for (const ing of ingresses) {
    for (const rule of ing.rules) {
      const target = services.find((s) => s.clusterId === ing.clusterId && s.namespace === ing.namespace && s.name === rule.serviceName);
      if (!target) continue;
      edges.push({ id: `${ing.id}-${target.id}`, source: ing.id, target: target.id, kind: 'routes_to', weight: 1, label: `${rule.host ?? '*'}${rule.path}`, metadata: {} });
    }
  }
  for (const svc of services) {
    for (const w of workloads) {
      if (svc.clusterId !== w.clusterId || svc.namespace !== w.namespace) continue;
      const matches = Object.entries(svc.selector).every(([k, v]) => w.labels[k] === v);
      if (!matches) continue;
      edges.push({ id: `${svc.id}-${w.id}`, source: svc.id, target: w.id, kind: 'selects', weight: 1, metadata: {} });
    }
  }
  return {
    id: 'tg-synth-1', tenantId, name: 'application', clusterId: cluster.id, group: 'cluster',
    nodes, edges,
    generatedAt: new Date().toISOString(),
  };
}

export function buildInventoryClient(deps: { logger: Logger }): InventoryClient {
  const provider: KubernetesProvider = buildFixtureProvider(deps.logger);
  return {
    async fetch(tenantId, clusterId) {
      const clusters = await provider.listClusters(tenantId);
      const target = clusterId ? clusters.filter((c) => c.id === clusterId) : clusters;
      const namespaces: Namespace[] = [];
      const workloads: Workload[] = [];
      const pods: Pod[] = [];
      const services: Service[] = [];
      const deployments: Deployment[] = [];
      const statefulsets: StatefulSet[] = [];
      const daemonsets: DaemonSet[] = [];
      const ingresses: Ingress[] = [];
      for (const cluster of target) {
        namespaces.push(...(await provider.listNamespaces(tenantId, cluster.id)));
        const opts: ListOptions = { clusterId: cluster.id };
        const [d, s, da, p, sv, ing] = await Promise.all([
          provider.listDeployments(tenantId, opts),
          provider.listStatefulSets(tenantId, opts),
          provider.listDaemonSets(tenantId, opts),
          provider.listPods(tenantId, opts),
          provider.listServices(tenantId, opts),
          provider.listIngresses(tenantId, opts),
        ]);
        deployments.push(...d);
        statefulsets.push(...s);
        daemonsets.push(...da);
        pods.push(...p);
        services.push(...sv);
        ingresses.push(...ing);
        workloads.push(...d, ...s, ...da);
      }
      const health = buildSyntheticHealth(tenantId, target, pods);
      const runtimeReport = buildSyntheticRuntime(tenantId, target, pods);
      const costAnalysis = target[0] ? buildSyntheticCost(tenantId, target[0], workloads) : undefined;
      const topology = target[0] ? buildSyntheticTopology(tenantId, target[0], workloads, services, ingresses) : undefined;
      return { clusters: target, namespaces, workloads, pods, services, deployments, statefulsets, daemonsets, ingresses, health, runtimeReport, costAnalysis, topology };
    },
  };
}
