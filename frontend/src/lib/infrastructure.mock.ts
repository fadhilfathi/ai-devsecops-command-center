/**
 * Sprint 4 — Mock data for the infrastructure dashboard modules.
 *
 * The shapes match the contract published by the four Sprint 4
 * services. Setting `USE_MOCKS = false` in `lib/api.ts` switches
 * the UI to live data with no caller changes.
 */

import type {
  Asset,
  Cluster,
  Namespace,
  Workload,
  Pod,
  K8sService,
  Deployment,
  Ingress,
  InfrastructureHealth,
  RuntimeRisk,
  RuntimeSecurityReport,
  CostAnalysis,
  WorkloadCost,
  CostFinding,
  CostRecommendation,
  TopologyGraph,
} from "@/types/infrastructure";

const NOW = (): string => new Date().toISOString();

export const mockClusters: Cluster[] = [
  {
    id: "11111111-1111-4111-8111-111111111111",
    tenantId: "00000000-0000-4000-8000-000000000001",
    name: "prod-us-east-1",
    server: "https://api.prod-use1.example.com:6443",
    provider: "eks",
    k8sVersion: "1.29",
    region: "us-east-1",
    environment: "prod",
    phase: "active",
    nodeCount: 6,
    readyNodes: 6,
    totalCpuCores: 48,
    totalMemoryBytes: 192 * 1024 * 1024 * 1024,
    nodes: [
      { name: "ip-10-0-2-10", roles: ["worker"], kubeletVersion: "v1.29.4", architecture: "amd64", conditions: ["ready"], unschedulable: false },
      { name: "ip-10-0-2-11", roles: ["worker"], kubeletVersion: "v1.29.4", architecture: "amd64", conditions: ["ready"], unschedulable: false },
      { name: "ip-10-0-2-12", roles: ["worker"], kubeletVersion: "v1.29.4", architecture: "amd64", conditions: ["disk_pressure"], unschedulable: false },
    ],
    labels: { env: "prod" },
    lastSyncedAt: NOW(),
  },
  {
    id: "22222222-2222-4222-8222-222222222222",
    tenantId: "00000000-0000-4000-8000-000000000001",
    name: "staging-eu-west-1",
    server: "https://api.staging-euw1.example.com:6443",
    provider: "gke",
    k8sVersion: "1.28",
    region: "europe-west1",
    environment: "staging",
    phase: "active",
    nodeCount: 3,
    readyNodes: 2,
    totalCpuCores: 12,
    totalMemoryBytes: 48 * 1024 * 1024 * 1024,
    nodes: [
      { name: "gke-staging-pool-1", roles: ["worker"], kubeletVersion: "v1.28.9", architecture: "amd64", conditions: ["ready"], unschedulable: false },
      { name: "gke-staging-pool-2", roles: ["worker"], kubeletVersion: "v1.28.9", architecture: "amd64", conditions: ["disk_pressure"], unschedulable: false },
    ],
    labels: { env: "staging" },
    lastSyncedAt: NOW(),
  },
];

export const mockNamespaces: Namespace[] = [
  { id: "ns-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", name: "default", phase: "active", workloadCount: 4, podCount: 8, runningPods: 7, pendingPods: 0, failedPods: 1, serviceCount: 5, restartsLast1h: 12, labels: {}, lastSyncedAt: NOW() },
  { id: "ns-2", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", name: "kube-system", phase: "active", workloadCount: 6, podCount: 12, runningPods: 12, pendingPods: 0, failedPods: 0, serviceCount: 4, restartsLast1h: 0, labels: {}, lastSyncedAt: NOW() },
  { id: "ns-3", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", name: "monitoring", phase: "active", workloadCount: 3, podCount: 6, runningPods: 5, pendingPods: 1, failedPods: 0, serviceCount: 2, restartsLast1h: 3, labels: {}, lastSyncedAt: NOW() },
];

export const mockWorkloads: Workload[] = [
  {
    id: "w-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", kind: "deployment", name: "payments-api", image: "ghcr.io/example/payments-api:1.42.0",
    imageDigest: "sha256:deadbeefcafe0000000000000000000000000000000000000000000000000000",
    replicas: { desired: 3, ready: 3, updated: 3, available: 3 },
    health: "healthy", conditions: [{ type: "Available", status: "true" }],
    labels: { app: "payments-api" },
    resources: { cpuRequestsMillicores: 250, cpuLimitsMillicores: 1000, memoryRequestsBytes: 512 * 1024 * 1024, memoryLimitsBytes: 1024 * 1024 * 1024 },
    lastSyncedAt: NOW(),
  },
  {
    id: "w-2", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", kind: "deployment", name: "legacy-batch", image: "example/legacy-batch:1.0",
    replicas: { desired: 2, ready: 2, updated: 2, available: 2 },
    health: "healthy", conditions: [{ type: "Available", status: "true" }],
    labels: { app: "legacy-batch" },
    resources: { cpuRequestsMillicores: 2000, cpuLimitsMillicores: 4000, memoryRequestsBytes: 8 * 1024 * 1024 * 1024, memoryLimitsBytes: 16 * 1024 * 1024 * 1024 },
    lastSyncedAt: NOW(),
  },
];

export const mockPods: Pod[] = [
  {
    id: "p-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", name: "payments-api-7d4f8b-abcd1", phase: "running", node: "ip-10-0-2-10", podIp: "10.42.0.10",
    ownerKind: "Deployment", ownerName: "payments-api", serviceAccount: "payments-api",
    containers: [{ name: "app", image: "ghcr.io/example/payments-api:1.42.0", state: "running", ready: true, restartCount: 0, lastTerminationReason: "unknown", privileged: false, runAsRoot: false, addedCapabilities: [], hostPaths: [] }],
    restarts: 0, lastTerminationReason: "unknown", labels: { app: "payments-api" },
  },
  {
    id: "p-2", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", name: "payments-api-7d4f8b-abcd2", phase: "pending",
    ownerKind: "Deployment", ownerName: "payments-api", serviceAccount: "default",
    containers: [{ name: "app", image: "ghcr.io/example/payments-api:1.42.0", state: "waiting", ready: false, restartCount: 8, lastTerminationReason: "crash_loop_back_off", privileged: false, runAsRoot: false, addedCapabilities: [], hostPaths: [] }],
    restarts: 8, lastTerminationReason: "crash_loop_back_off", labels: { app: "payments-api" },
  },
];

export const mockServices: K8sService[] = [
  {
    id: "s-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", name: "payments-api", type: "cluster_ip", clusterIp: "10.96.0.10",
    selector: { app: "payments-api" }, ports: [{ name: "http", protocol: "TCP", port: 80, targetPort: 8080 }],
    fqdn: "payments-api.default.svc.cluster.local", hasReadyEndpoints: true,
    labels: { app: "payments-api" },
  },
];

export const mockDeployments: Deployment[] = [
  {
    id: "d-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", name: "payments-api", image: "ghcr.io/example/payments-api:1.42.0",
    replicas: { desired: 3, ready: 3, updated: 3, available: 3 },
    health: "healthy", strategy: "rolling_update", rollout: "complete", paused: false, changeCause: "sprint-4 release",
    lastSyncedAt: NOW(),
  },
];

export const mockIngresses: Ingress[] = [
  {
    id: "i-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", name: "public", className: "nginx",
    rules: [{ host: "api.example.com", path: "/payments", pathType: "Prefix", serviceName: "payments-api", servicePort: 80 }],
    tls: [{ hosts: ["api.example.com"], secretName: "api-tls" }],
  },
];

export const mockHealth: InfrastructureHealth[] = [
  {
    id: "h-1", tenantId: "00000000-0000-4000-8000-000000000001", scope: "cluster",
    subject: { kind: "Cluster", name: "prod-us-east-1", clusterId: "11111111-1111-4111-8111-111111111111" },
    score: { score: 78, band: "C", status: "degraded", counts: { critical: 1, high: 2, medium: 3, low: 1, info: 0 }, generatedAt: NOW() },
    issues: [
      { id: "iss-1", kind: "crash_loop_back_off", severity: "critical", message: "Container app is in CrashLoopBackOff", subject: { kind: "Pod", name: "payments-api-7d4f8b-abcd2", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111" }, detectedAt: NOW(), remediation: "kubectl rollout restart" },
      { id: "iss-2", kind: "node_pressure", severity: "high", message: "Node ip-10-0-2-12 reports condition: disk_pressure", subject: { kind: "Node", name: "ip-10-0-2-12", clusterId: "11111111-1111-4111-8111-111111111111" }, detectedAt: NOW() },
    ],
    recommendations: [
      { id: "r-1", priority: "p0", title: "Restart crashing workloads", detail: "1 pod(s) are in CrashLoopBackOff.", action: "kubectl rollout restart deploy -n default payments-api", ruleIds: ["crash_loop_back_off"], affectedCount: 1 },
      { id: "r-2", priority: "p2", title: "Resolve node pressure", detail: "1 node(s) report pressure.", action: "kubectl drain ip-10-0-2-12", ruleIds: ["node_pressure"], affectedCount: 1 },
    ],
    generatedAt: NOW(),
  },
];

export const mockRuntimeRisks: RuntimeRisk[] = [
  {
    id: "rr-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", subject: "pod", subjectKind: "Pod", subjectName: "legacy-tool-1-abcd",
    ruleId: "AICC-RT-001", ruleName: "Privileged container", category: "privileged_container",
    level: "critical", severity: "critical",
    message: "Container app runs in privileged mode",
    evidencePath: "pod.spec.containers[app].securityContext.privileged", evidenceValue: true,
    remediation: "Drop securityContext.privileged and use a narrowly-scoped capabilities set.",
    references: ["https://www.cisecurity.org/benchmark/kubernetes"],
    detectedAt: NOW(),
  },
  {
    id: "rr-2", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1",
    namespace: "default", subject: "pod", subjectKind: "Pod", subjectName: "legacy-tool-1-abcd",
    ruleId: "AICC-RT-004", ruleName: "Dangerous Linux capability", category: "dangerous_capability",
    level: "critical", severity: "critical",
    message: "Container app adds dangerous capability SYS_ADMIN",
    evidencePath: "pod.spec.containers[app].securityContext.capabilities.add", evidenceValue: "SYS_ADMIN",
    remediation: "Drop the dangerous capability. If required, use capabilities.add with the minimal set.",
    references: ["https://www.cisecurity.org/benchmark/kubernetes"],
    detectedAt: NOW(),
  },
];

export const mockRuntimeReport: RuntimeSecurityReport = {
  id: "rsr-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111",
  windowStart: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), windowEnd: NOW(),
  riskLevel: "critical", score: 28,
  counts: { critical: 2, high: 3, medium: 1, low: 0 },
  categoryCounts: { privileged_container: 1, dangerous_capability: 1, root_user: 1, image_risk: 1, unsafe_security_context: 1 },
  findings: mockRuntimeRisks,
  recommendations: [
    { id: "rec-1", title: "Fix: Privileged container", detail: "Drop securityContext.privileged and use a narrowly-scoped capabilities set.", level: "critical", affectedCount: 1 },
    { id: "rec-2", title: "Fix: Dangerous Linux capability", detail: "Drop the dangerous capability. If required, use capabilities.add with the minimal set.", level: "critical", affectedCount: 1 },
  ],
  generatedAt: NOW(),
};

export const mockWorkloadCosts: WorkloadCost[] = [
  { workloadId: "w-1", workloadName: "payments-api", namespace: "default", kind: "deployment", currentMonthlyUsd: 86.4, recommendedMonthlyUsd: 86.4, potentialMonthlySavingsUsd: 0, utilisation: { cpuP50: 0.4, cpuP95: 0.6, memoryP50: 0.5, memoryP95: 0.7 }, requests: { cpuMillicores: 250, memoryBytes: 512 * 1024 * 1024 }, limits: { cpuMillicores: 1000, memoryBytes: 1024 * 1024 * 1024 } },
  { workloadId: "w-2", workloadName: "legacy-batch", namespace: "default", kind: "deployment", currentMonthlyUsd: 1305.6, recommendedMonthlyUsd: 408.0, potentialMonthlySavingsUsd: 897.6, utilisation: { cpuP50: 0.05, cpuP95: 0.12, memoryP50: 0.1, memoryP95: 0.2 }, requests: { cpuMillicores: 2000, memoryBytes: 8 * 1024 * 1024 * 1024 }, limits: { cpuMillicores: 4000, memoryBytes: 16 * 1024 * 1024 * 1024 } },
];

export const mockCostFindings: CostFinding[] = [
  { id: "cf-1", kind: "under_utilized_cpu", dimension: "cpu", severity: "medium", message: "CPU p95 12% is well below request", workloadId: "w-2", workloadName: "legacy-batch", namespace: "default", monthlySavingsUsd: 720, data: {}, detectedAt: NOW() },
  { id: "cf-2", kind: "under_utilized_memory", dimension: "memory", severity: "medium", message: "Memory p95 20% is well below request", workloadId: "w-2", workloadName: "legacy-batch", namespace: "default", monthlySavingsUsd: 180, data: {}, detectedAt: NOW() },
];

export const mockCostRecommendations: CostRecommendation[] = [
  { id: "cr-1", action: "right_size_requests", priority: "p2", title: "Right-size CPU requests", detail: "Reduce CPU requests to better match observed p95 utilisation.", workloadIds: ["w-2"], monthlySavingsUsd: 720, annualSavingsUsd: 8640, createdAt: NOW() },
  { id: "cr-2", action: "right_size_requests", priority: "p2", title: "Right-size memory requests", detail: "Reduce memory requests to better match observed p95 utilisation.", workloadIds: ["w-2"], monthlySavingsUsd: 180, annualSavingsUsd: 2160, createdAt: NOW() },
];

export const mockCostAnalysis: CostAnalysis = {
  id: "ca-1", tenantId: "00000000-0000-4000-8000-000000000001", clusterId: "11111111-1111-4111-8111-111111111111",
  windowStart: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), windowEnd: NOW(),
  pricing: { cpuUsdPerHour: 0.041, memoryUsdPerHour: 0.005, currency: "USD" },
  currentMonthlyUsd: 1392, recommendedMonthlyUsd: 494, potentialMonthlySavingsUsd: 898,
  workloads: mockWorkloadCosts, findings: mockCostFindings, recommendations: mockCostRecommendations,
  generatedAt: NOW(),
};

export const mockTopologyGraph: TopologyGraph = {
  id: "tg-1", tenantId: "00000000-0000-4000-8000-000000000001", name: "application", group: "tenant",
  nodes: [
    { id: "ing-1", label: "public", kind: "ingress", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", riskScore: 0, tags: ["class=nginx"], metadata: {} },
    { id: "svc-1", label: "payments-api", kind: "service", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", riskScore: 30, tags: ["app=payments-api"], metadata: {} },
    { id: "wl-1", label: "payments-api", kind: "workload", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", riskScore: 0, tags: ["kind=deployment"], metadata: {} },
  ],
  edges: [
    { id: "e-1", source: "ing-1", target: "svc-1", kind: "routes_to", weight: 1, label: "api.example.com/payments→:80", metadata: {} },
    { id: "e-2", source: "svc-1", target: "wl-1", kind: "selects", weight: 1, label: "app=payments-api", metadata: {} },
  ],
  generatedAt: NOW(),
};

export const mockAssets: Asset[] = [
  { id: "a-1", tenantId: "00000000-0000-4000-8000-000000000001", kind: "cluster", name: "prod-us-east-1", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", labels: { env: "prod" }, metadata: {} },
  { id: "a-2", tenantId: "00000000-0000-4000-8000-000000000001", kind: "namespace", name: "default", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", labels: {}, metadata: {} },
  { id: "a-3", tenantId: "00000000-0000-4000-8000-000000000001", kind: "service", name: "payments-api", namespace: "default", clusterId: "11111111-1111-4111-8111-111111111111", clusterName: "prod-us-east-1", labels: { app: "payments-api" }, metadata: {} },
];
