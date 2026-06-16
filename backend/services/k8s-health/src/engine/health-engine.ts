/**
 * K8s Health Engine.
 *
 * Pure functions: given a snapshot of inventory (clusters,
 * namespaces, workloads, pods), produce health scores, issues,
 * and recommendations. No I/O, no event-bus side effects.
 *
 * Scoring model (0..100, higher = healthier):
 *   - 100 - 8 * critical_issue_count
 *   - 4  * high_issue_count
 *   - 2  * medium_issue_count
 *   - 1  * low_issue_count
 *   - 0.5 * info_issue_count
 * Floored at 0.
 *
 * Detection rules (in evaluation order):
 *   1. CrashLoopBackOff — pod.lastTerminationReason === 'crash_loop_back_off'
 *   2. ImagePullBackOff — 'image_pull_back_off' / 'err_image_pull'
 *   3. OOMKilled        — pod.lastTerminationReason === 'oom_killed'
 *   4. Pending pod      — pod.phase === 'pending'
 *   5. Failed pod       — pod.phase === 'failed'
 *   6. Restart storm    — sum(container.restartCount) >= 5 over all
 *                          containers of a pod
 *   7. Node pressure    — cluster nodes with conditions other than
 *                          'ready'
 *   8. Unschedulable    — workload.replicas.ready == 0 and
 *                          workload.replicas.desired > 0 and
 *                          at least one node is unschedulable /
 *                          has pressure
 */
import { randomUUID } from 'node:crypto';
import type {
  Cluster,
  Namespace,
  Workload,
  Pod,
  HealthIssue,
  HealthRecommendation,
  HealthScore,
  InfrastructureHealth,
  HealthBand,
  HealthStatus,
  HealthIssueSeverity,
  HealthIssueKind,
} from '@aicc/models';
import type { Logger } from '@aicc/shared';

export interface HealthEngineInput {
  clusters: Cluster[];
  namespaces: Namespace[];
  workloads: Workload[];
  pods: Pod[];
}

export interface HealthEngine {
  score(input: HealthEngineInput): InfrastructureHealth[];
  scoreCluster(cluster: Cluster, pods: Pod[], workloads: Workload[]): InfrastructureHealth;
  scoreNamespace(ns: Namespace, pods: Pod[], workloads: Workload[]): InfrastructureHealth;
  scoreWorkload(workload: Workload, pods: Pod[]): InfrastructureHealth;
  scorePod(pod: Pod): InfrastructureHealth;
  collectIssues(input: HealthEngineInput): HealthIssue[];
  recommend(input: HealthEngineInput, issues: HealthIssue[]): HealthRecommendation[];
}

export interface HealthEngineDeps {
  logger: Logger;
}

const WEIGHTS: Record<HealthIssueSeverity, number> = {
  critical: 8,
  high: 4,
  medium: 2,
  low: 1,
  info: 0.5,
};

function bandFor(score: number): HealthBand {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function statusFor(score: number): HealthStatus {
  if (score >= 90) return 'healthy';
  if (score >= 70) return 'degraded';
  if (score > 0) return 'unhealthy';
  return 'unknown';
}

function buildScore(issues: HealthIssue[]): HealthScore {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const i of issues) {
    counts[i.severity] = (counts[i.severity] ?? 0) + 1;
  }
  let score = 100;
  for (const sev of Object.keys(counts) as HealthIssueSeverity[]) {
    score -= WEIGHTS[sev] * (counts[sev] ?? 0);
  }
  score = Math.max(0, Math.round(score));
  return {
    score,
    band: bandFor(score),
    status: statusFor(score),
    counts,
    generatedAt: new Date().toISOString(),
  };
}

function makeIssue(
  kind: HealthIssueKind,
  severity: HealthIssueSeverity,
  message: string,
  subject: { kind: string; name: string; namespace?: string; clusterId?: string },
  remediation?: string,
): HealthIssue {
  return {
    id: randomUUID(),
    kind,
    severity,
    message,
    subject,
    remediation,
    detectedAt: new Date().toISOString(),
  };
}

function detectPodIssues(pod: Pod): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const subject = {
    kind: 'Pod',
    name: pod.name,
    namespace: pod.namespace,
    clusterId: pod.clusterId,
  };

  // Per-container termination reasons.
  for (const c of pod.containers) {
    if (c.lastTerminationReason === 'crash_loop_back_off') {
      issues.push(makeIssue(
        'crash_loop_back_off',
        'critical',
        `Container ${c.name} is in CrashLoopBackOff (restarts: ${c.restartCount})`,
        subject,
        `Inspect logs: kubectl logs ${pod.name} -n ${pod.namespace} --previous`,
      ));
    } else if (
      c.lastTerminationReason === 'image_pull_back_off' ||
      c.lastTerminationReason === 'err_image_pull' ||
      c.lastTerminationReason === 'err_image_never_pull' ||
      c.lastTerminationReason === 'create_container_config_error' ||
      c.lastTerminationReason === 'invalid_image_name'
    ) {
      issues.push(makeIssue(
        'image_pull_back_off',
        'high',
        `Container ${c.name} failed to pull image (${c.image})`,
        subject,
        `Verify image and pull secrets: kubectl describe pod ${pod.name} -n ${pod.namespace}`,
      ));
    } else if (c.lastTerminationReason === 'oom_killed') {
      issues.push(makeIssue(
        'oom_killed',
        'high',
        `Container ${c.name} was OOMKilled`,
        subject,
        `Increase memory limits or profile memory use`,
      ));
    }
  }

  // Pod-level restart storm.
  const totalRestarts = pod.containers.reduce((s, c) => s + c.restartCount, 0);
  if (totalRestarts >= 5) {
    issues.push(makeIssue(
      'restart_storm',
      'critical',
      `Pod has restarted ${totalRestarts} times`,
      subject,
      `kubectl rollout restart deploy -n ${pod.namespace} ${pod.ownerName ?? ''}`.trim(),
    ));
  }

  // Phase checks.
  if (pod.phase === 'pending') {
    issues.push(makeIssue(
      'pending_pod',
      'high',
      'Pod is pending — likely unschedulable',
      subject,
      `kubectl describe pod ${pod.name} -n ${pod.namespace} for scheduling events`,
    ));
  }
  if (pod.phase === 'failed') {
    issues.push(makeIssue(
      'failed_pod',
      'critical',
      'Pod is in Failed phase',
      subject,
      'Inspect `kubectl describe pod` and `kubectl logs --previous`',
    ));
  }

  return issues;
}

function detectWorkloadIssues(workload: Workload, pods: Pod[]): HealthIssue[] {
  const issues: HealthIssue[] = [];
  const subject = {
    kind: workload.kind,
    name: workload.name,
    namespace: workload.namespace,
    clusterId: workload.clusterId,
  };
  const { desired, ready, available } = workload.replicas;
  if (desired > 0 && ready < desired) {
    issues.push(makeIssue(
      'unschedulable_workload',
      ready === 0 ? 'critical' : 'high',
      `Workload has ${ready}/${desired} ready replicas`,
      subject,
      `kubectl rollout status deploy -n ${workload.namespace} ${workload.name}`,
    ));
  }
  void available;
  void pods;
  return issues;
}

function detectNodeIssues(cluster: Cluster): HealthIssue[] {
  const issues: HealthIssue[] = [];
  for (const node of cluster.nodes) {
    if (node.unschedulable) {
      issues.push(makeIssue(
        'node_pressure',
        'high',
        `Node ${node.name} is unschedulable`,
        { kind: 'Node', name: node.name, clusterId: cluster.id },
        `kubectl uncordon ${node.name}`,
      ));
      continue;
    }
    for (const cond of node.conditions) {
      if (cond === 'ready') continue;
      const sev: HealthIssueSeverity = cond === 'network_unavailable' ? 'critical' : 'high';
      issues.push(makeIssue(
        'node_pressure',
        sev,
        `Node ${node.name} reports condition: ${cond}`,
        { kind: 'Node', name: node.name, clusterId: cluster.id },
        `kubectl describe node ${node.name}`,
      ));
    }
  }
  return issues;
}

function buildRecommendations(issues: HealthIssue[]): HealthRecommendation[] {
  const recs: HealthRecommendation[] = [];
  const seen = new Set<string>();

  // Helper to push a recommendation if not already present.
  function push(priority: 'p0' | 'p1' | 'p2' | 'p3', title: string, detail: string, action: string, ruleIds: string[], affected: number) {
    const key = `${title}::${action}`;
    if (seen.has(key)) return;
    seen.add(key);
    recs.push({
      id: randomUUID(),
      priority,
      title,
      detail,
      action,
      ruleIds,
      affectedCount: affected,
    });
  }

  // CrashLoopBackOff → restart
  const clboCount = issues.filter((i) => i.kind === 'crash_loop_back_off').length;
  if (clboCount > 0) {
    push(
      'p0',
      'Restart crashing workloads',
      `${clboCount} pod(s) are in CrashLoopBackOff. Roll the affected deployments to clear the bad state, then inspect logs for the root cause.`,
      'kubectl rollout restart deploy -n <namespace> <deployment>',
      ['crash_loop_back_off'],
      clboCount,
    );
  }

  const pendingCount = issues.filter((i) => i.kind === 'pending_pod' || i.kind === 'unschedulable_workload').length;
  if (pendingCount > 0) {
    push(
      'p1',
      'Address pending / unschedulable pods',
      `${pendingCount} pod(s) are pending or unschedulable. Check node capacity, taints, and resource requests.`,
      'kubectl describe pod -n <namespace> <pod>',
      ['pending_pod', 'unschedulable_workload'],
      pendingCount,
    );
  }

  const oomCount = issues.filter((i) => i.kind === 'oom_killed').length;
  if (oomCount > 0) {
    push(
      'p1',
      'Raise memory limits or fix leaks',
      `${oomCount} pod(s) were OOMKilled. Increase memory limits or fix the underlying memory leak.`,
      'kubectl set resources deploy/<name> -n <ns> --limits=memory=<value>',
      ['oom_killed'],
      oomCount,
    );
  }

  const imgCount = issues.filter((i) => i.kind === 'image_pull_back_off').length;
  if (imgCount > 0) {
    push(
      'p1',
      'Fix image pull errors',
      `${imgCount} pod(s) failed to pull their image. Verify the image name, tag, and pull secrets.`,
      'kubectl describe pod -n <namespace> <pod>',
      ['image_pull_back_off'],
      imgCount,
    );
  }

  const restartCount = issues.filter((i) => i.kind === 'restart_storm').length;
  if (restartCount > 0) {
    push(
      'p0',
      'Investigate restart storms',
      `${restartCount} pod(s) show a restart storm. Roll forward or back to a known good revision.`,
      'kubectl rollout undo deploy/<name> -n <ns>',
      ['restart_storm'],
      restartCount,
    );
  }

  const nodeCount = issues.filter((i) => i.kind === 'node_pressure').length;
  if (nodeCount > 0) {
    push(
      'p2',
      'Resolve node pressure',
      `${nodeCount} node(s) report pressure or unschedulable state. Drain, repair, and re-cordon.`,
      'kubectl drain <node> --ignore-daemonsets && kubectl uncordon <node>',
      ['node_pressure'],
      nodeCount,
    );
  }

  return recs.sort((a, b) => a.priority.localeCompare(b.priority));
}

export function buildHealthEngine(deps: HealthEngineDeps): HealthEngine {
  void deps;
  return {
    score(input) {
      const clusterHealth = input.clusters.map((c) => {
        const pods = input.pods.filter((p) => p.clusterId === c.id);
        const workloads = input.workloads.filter((w) => w.clusterId === c.id);
        return this.scoreCluster(c, pods, workloads);
      });
      const namespaceHealth = input.namespaces.map((n) => {
        const pods = input.pods.filter((p) => p.clusterId === n.clusterId && p.namespace === n.name);
        const workloads = input.workloads.filter(
          (w) => w.clusterId === n.clusterId && w.namespace === n.name,
        );
        return this.scoreNamespace(n, pods, workloads);
      });
      const workloadHealth = input.workloads.map((w) => {
        const pods = input.pods.filter(
          (p) => p.clusterId === w.clusterId && p.namespace === w.namespace && p.ownerName === w.name,
        );
        return this.scoreWorkload(w, pods);
      });
      const podHealth = input.pods.map((p) => this.scorePod(p));
      return [...clusterHealth, ...namespaceHealth, ...workloadHealth, ...podHealth];
    },

    scoreCluster(cluster, pods, workloads) {
      const podIssues = pods.flatMap(detectPodIssues);
      const wlIssues = workloads.flatMap(detectWorkloadIssues);
      const nodeIssues = detectNodeIssues(cluster);
      const issues = [...podIssues, ...wlIssues, ...nodeIssues];
      const score = buildScore(issues);
      return {
        id: randomUUID(),
        tenantId: cluster.tenantId,
        scope: 'cluster',
        subject: { kind: 'Cluster', name: cluster.name, clusterId: cluster.id },
        score,
        issues,
        recommendations: buildRecommendations(issues),
        generatedAt: new Date().toISOString(),
      };
    },

    scoreNamespace(ns, pods, workloads) {
      const podIssues = pods.flatMap(detectPodIssues);
      const wlIssues = workloads.flatMap(detectWorkloadIssues);
      const issues = [...podIssues, ...wlIssues];
      const score = buildScore(issues);
      return {
        id: randomUUID(),
        tenantId: ns.tenantId,
        scope: 'namespace',
        subject: { kind: 'Namespace', name: ns.name, namespace: ns.name, clusterId: ns.clusterId },
        score,
        issues,
        recommendations: buildRecommendations(issues),
        generatedAt: new Date().toISOString(),
      };
    },

    scoreWorkload(workload, pods) {
      const podIssues = pods.flatMap(detectPodIssues);
      const wlIssues = detectWorkloadIssues(workload, pods);
      const issues = [...podIssues, ...wlIssues];
      const score = buildScore(issues);
      return {
        id: randomUUID(),
        tenantId: workload.tenantId,
        scope: 'workload',
        subject: {
          kind: workload.kind,
          name: workload.name,
          namespace: workload.namespace,
          clusterId: workload.clusterId,
        },
        score,
        issues,
        recommendations: buildRecommendations(issues),
        generatedAt: new Date().toISOString(),
      };
    },

    scorePod(pod) {
      const issues = detectPodIssues(pod);
      const score = buildScore(issues);
      return {
        id: randomUUID(),
        tenantId: pod.tenantId,
        scope: 'pod',
        subject: {
          kind: 'Pod',
          name: pod.name,
          namespace: pod.namespace,
          clusterId: pod.clusterId,
        },
        score,
        issues,
        recommendations: buildRecommendations(issues),
        generatedAt: new Date().toISOString(),
      };
    },

    collectIssues(input) {
      return [
        ...input.pods.flatMap(detectPodIssues),
        ...input.workloads.flatMap((w) => detectWorkloadIssues(w, input.pods)),
        ...input.clusters.flatMap(detectNodeIssues),
      ];
    },

    recommend(_input, issues) {
      return buildRecommendations(issues);
    },
  };
}
