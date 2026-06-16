/**
 * Sprint 4 — Infrastructure Intelligence types.
 *
 * Mirrors the contracts published by the four Sprint 4 services:
 *   - `@aicc/kubernetes-service` (port 4006)
 *   - `@aicc/k8s-health-service` (port 4007)
 *   - `@aicc/runtime-security-service` (port 4008)
 *   - `@aicc/inventory-service` (port 4009)
 *   - `@aicc/cost-intelligence-service` (port 4010)
 *   - `@aicc/topology-service` (port 4011)
 *
 * When the API gateway emits OpenAPI, we can codegen these from
 * the Zod schemas in `backend/models/infrastructure/`.
 */

import type { Severity } from "./index";

// ---- Common ---------------------------------------------------------

export type ClusterProvider =
  | "eks"
  | "gke"
  | "aks"
  | "oke"
  | "openshift"
  | "rancher"
  | "kind"
  | "k3s"
  | "self_managed"
  | "unknown";

export type ClusterPhase =
  | "provisioning"
  | "active"
  | "degraded"
  | "draining"
  | "archived";

export type HealthBand = "A" | "B" | "C" | "D" | "F";

export type HealthStatus = "healthy" | "degraded" | "unhealthy" | "unknown";

export type RiskLevel = "critical" | "high" | "medium" | "low";

// ---- Cluster / Namespace / Workload / Pod / Service / Deployment ----

export interface Cluster {
  id: string;
  tenantId: string;
  name: string;
  server?: string;
  provider: ClusterProvider;
  k8sVersion?: string;
  region?: string;
  environment: "prod" | "staging" | "dev" | "sandbox";
  phase: ClusterPhase;
  nodeCount: number;
  readyNodes: number;
  totalCpuCores: number;
  totalMemoryBytes: number;
  nodes: Array<{
    name: string;
    roles: string[];
    kubeletVersion?: string;
    architecture?: string;
    conditions: string[];
    unschedulable: boolean;
  }>;
  labels: Record<string, string>;
  lastSyncedAt?: string;
}

export interface Namespace {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  name: string;
  phase: "active" | "terminating";
  workloadCount: number;
  podCount: number;
  runningPods: number;
  pendingPods: number;
  failedPods: number;
  serviceCount: number;
  restartsLast1h: number;
  labels: Record<string, string>;
  lastSyncedAt?: string;
}

export type WorkloadKind =
  | "deployment"
  | "statefulset"
  | "daemonset"
  | "replicaset"
  | "cronjob"
  | "job"
  | "pod";

export type WorkloadHealth = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface Workload {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespaceId?: string;
  namespace: string;
  kind: WorkloadKind;
  name: string;
  image?: string;
  imageDigest?: string;
  replicas: {
    desired: number;
    ready: number;
    updated: number;
    available: number;
  };
  health: WorkloadHealth;
  conditions: Array<{
    type: string;
    status: "true" | "false" | "unknown";
    message?: string;
    lastTransitionTime?: string;
  }>;
  labels: Record<string, string>;
  resources: {
    cpuRequestsMillicores: number;
    cpuLimitsMillicores: number;
    memoryRequestsBytes: number;
    memoryLimitsBytes: number;
  };
  lastSyncedAt?: string;
}

export interface Pod {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  name: string;
  phase: "pending" | "running" | "succeeded" | "failed" | "unknown";
  node?: string;
  podIp?: string;
  ownerKind?: string;
  ownerName?: string;
  serviceAccount?: string;
  containers: Array<{
    name: string;
    image: string;
    state: "waiting" | "running" | "terminated";
    ready: boolean;
    restartCount: number;
    lastTerminationReason: string;
    privileged: boolean;
    runAsRoot: boolean;
    addedCapabilities: string[];
    hostPaths: string[];
  }>;
  restarts: number;
  lastTerminationReason: string;
  labels: Record<string, string>;
}

export interface K8sService {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  name: string;
  type: "cluster_ip" | "node_port" | "load_balancer" | "external_name";
  clusterIp?: string;
  selector: Record<string, string>;
  ports: Array<{
    name?: string;
    protocol: "TCP" | "UDP" | "SCTP";
    port: number;
    targetPort?: number | string;
    nodePort?: number;
  }>;
  fqdn?: string;
  hasReadyEndpoints: boolean;
  labels: Record<string, string>;
}

export interface Deployment {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  name: string;
  image?: string;
  replicas: { desired: number; ready: number; updated: number; available: number };
  health: WorkloadHealth;
  strategy: "rolling_update" | "recreate" | "in_place";
  rollout: "complete" | "progressing" | "paused" | "failed" | "unknown";
  paused: boolean;
  changeCause?: string;
  lastSyncedAt?: string;
}

export interface Ingress {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  name: string;
  className: string;
  rules: Array<{
    host?: string;
    path: string;
    pathType: "Exact" | "Prefix" | "ImplementationSpecific";
    serviceName: string;
    servicePort: number | string;
  }>;
  tls: Array<{ hosts: string[]; secretName?: string }>;
}

// ---- Health ---------------------------------------------------------

export interface HealthIssue {
  id: string;
  kind:
    | "crash_loop_back_off"
    | "image_pull_back_off"
    | "oom_killed"
    | "pending_pod"
    | "failed_pod"
    | "restart_storm"
    | "node_pressure"
    | "unschedulable_workload"
    | "runtime_risk"
    | "cost_anomaly"
    | "unknown";
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  subject: { kind: string; name: string; namespace?: string; clusterId?: string };
  detectedAt: string;
  remediation?: string;
}

export interface HealthScore {
  score: number; // 0..100
  band: HealthBand;
  status: HealthStatus;
  counts: { critical: number; high: number; medium: number; low: number; info: number };
  generatedAt: string;
}

export interface InfrastructureHealth {
  id: string;
  tenantId: string;
  scope: "cluster" | "namespace" | "workload" | "pod";
  subject: { kind: string; name: string; namespace?: string; clusterId?: string };
  score: HealthScore;
  issues: HealthIssue[];
  recommendations: Array<{
    id: string;
    priority: "p0" | "p1" | "p2" | "p3";
    title: string;
    detail: string;
    action?: string;
    ruleIds: string[];
    affectedCount: number;
  }>;
  generatedAt: string;
}

// ---- Runtime security -----------------------------------------------

export type RiskCategory =
  | "privileged_container"
  | "host_path_volume"
  | "host_network"
  | "host_pid"
  | "host_ipc"
  | "root_user"
  | "dangerous_capability"
  | "unsafe_security_context"
  | "service_account_risk"
  | "rbac_risk"
  | "image_risk"
  | "network_policy_missing"
  | "resource_limits_missing"
  | "secrets_in_env"
  | "automount_service_account_token"
  | "unknown";

export interface RuntimeRisk {
  id: string;
  tenantId: string;
  clusterId: string;
  clusterName: string;
  namespace: string;
  subject:
    | "pod"
    | "workload"
    | "service"
    | "service_account"
    | "role_binding"
    | "cluster_role_binding"
    | "ingress"
    | "config_map"
    | "secret"
    | "unknown";
  subjectKind: string;
  subjectName: string;
  ruleId: string;
  ruleName: string;
  category: RiskCategory;
  level: RiskLevel;
  severity: Severity;
  message: string;
  evidencePath?: string;
  evidenceValue?: string | number | boolean | null;
  remediation: string;
  references: string[];
  detectedAt: string;
}

export interface RuntimeSecurityReport {
  id: string;
  tenantId: string;
  clusterId?: string;
  windowStart: string;
  windowEnd: string;
  riskLevel: RiskLevel;
  score: number;
  counts: { critical: number; high: number; medium: number; low: number };
  categoryCounts: Record<string, number>;
  findings: RuntimeRisk[];
  recommendations: Array<{
    id: string;
    title: string;
    detail: string;
    level: RiskLevel;
    affectedCount: number;
  }>;
  generatedAt: string;
}

// ---- Cost -----------------------------------------------------------

export interface WorkloadCost {
  workloadId: string;
  workloadName: string;
  namespace: string;
  kind: string;
  currentMonthlyUsd: number;
  recommendedMonthlyUsd: number;
  potentialMonthlySavingsUsd: number;
  utilisation: { cpuP50: number; cpuP95: number; memoryP50: number; memoryP95: number };
  requests: { cpuMillicores: number; memoryBytes: number };
  limits: { cpuMillicores: number; memoryBytes: number };
}

export interface CostFinding {
  id: string;
  kind:
    | "over_provisioned_cpu"
    | "over_provisioned_memory"
    | "under_utilized_cpu"
    | "under_utilized_memory"
    | "missing_requests"
    | "missing_limits"
    | "noisy_neighbour"
    | "cold_workload";
  severity: Severity;
  message: string;
  dimension?: "cpu" | "memory";
  workloadId?: string;
  workloadName?: string;
  namespace?: string;
  monthlySavingsUsd: number;
  data: Record<string, unknown>;
  detectedAt: string;
}

export interface CostRecommendation {
  id: string;
  action:
    | "right_size_requests"
    | "right_size_limits"
    | "add_limits"
    | "add_requests"
    | "remove_unused_workload"
    | "consolidate_replicas"
    | "use_spot_or_preemptible"
    | "unknown";
  priority: "p0" | "p1" | "p2" | "p3";
  title: string;
  detail: string;
  workloadIds: string[];
  monthlySavingsUsd: number;
  annualSavingsUsd: number;
  createdAt: string;
}

export interface CostAnalysis {
  id: string;
  tenantId: string;
  clusterId?: string;
  windowStart: string;
  windowEnd: string;
  pricing: { cpuUsdPerHour: number; memoryUsdPerHour: number; currency: string };
  currentMonthlyUsd: number;
  recommendedMonthlyUsd: number;
  potentialMonthlySavingsUsd: number;
  workloads: WorkloadCost[];
  findings: CostFinding[];
  recommendations: CostRecommendation[];
  generatedAt: string;
}

// ---- Topology -------------------------------------------------------

export type TopologyNodeKind =
  | "cluster"
  | "namespace"
  | "service"
  | "workload"
  | "pod"
  | "ingress"
  | "external";

export type TopologyEdgeKind =
  | "depends_on"
  | "routes_to"
  | "exposes"
  | "owns"
  | "calls"
  | "selects"
  | "in_namespace"
  | "unknown";

export interface TopologyNode {
  id: string;
  label: string;
  kind: TopologyNodeKind;
  namespace?: string;
  clusterId?: string;
  clusterName?: string;
  riskScore: number;
  tags: string[];
  position?: { x: number; y: number };
  metadata: Record<string, unknown>;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  kind: TopologyEdgeKind;
  weight: number;
  label?: string;
  metadata: Record<string, unknown>;
}

export interface TopologyGraph {
  id: string;
  tenantId: string;
  name: string;
  clusterId?: string;
  namespace?: string;
  group?: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  generatedAt: string;
}

// ---- Inventory ------------------------------------------------------

export type AssetKind =
  | "cluster"
  | "namespace"
  | "service"
  | "deployment"
  | "statefulset"
  | "daemonset"
  | "ingress"
  | "workload"
  | "pod";

export interface Asset {
  id: string;
  tenantId: string;
  kind: AssetKind;
  name: string;
  namespace?: string;
  clusterId: string;
  clusterName: string;
  labels: Record<string, string>;
  metadata: Record<string, unknown>;
}
