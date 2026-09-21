/**
 * Thin, typed API client used by every AionUi page.
 *
 * In Sprint 1 the client returned mock data from `lib/mock.ts`. In
 * Sprint 2 we add the security endpoints (S2.5) and the graph/SBOM
 * detail endpoints. The `USE_MOCKS` toggle lets pages render before
 * the S2.5 API is deployed.
 */

import type {
  Asset,
  ComplianceControl,
  EventStreamEntry,
  GraphData,
  Incident,
  Integration,
  Kpi,
  RiskHeatmap,
  SbomDocument,
  SecurityScore,
  SbomComponentEnhanced,
  VulnTimelinePoint,
  VulnTimelineRange,
  Vulnerability,
} from "@/types";
import type {
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
  CostFinding,
  CostRecommendation,
  WorkloadCost,
  TopologyGraph,
} from "@/types/infrastructure";
import {
  mockAssets,
  mockCompliance,
  mockEvents,
  mockGraphData,
  mockIncidents,
  mockIntegrations,
  mockKpis,
  mockRiskHeatmap,
  mockSbomDocument,
  mockSbomFull,
  mockSecurityScore,
  mockVulnTimeline,
  mockVulnerabilities,
} from "./mock";
import {
  mockClusters,
  mockNamespaces,
  mockWorkloads,
  mockPods,
  mockServices,
  mockDeployments,
  mockIngresses,
  mockHealth,
  mockRuntimeRisks,
  mockRuntimeReport,
  mockCostAnalysis,
  mockCostFindings,
  mockCostRecommendations,
  mockWorkloadCosts,
  mockTopologyGraph,
} from "./infrastructure.mock";

const USE_MOCKS = true; // flip to false once S2.5 API is deployed

async function get<T>(path: string, fallback: T): Promise<T> {
  if (USE_MOCKS) {
    // Simulate a small network delay so loading states are exercised.
    await new Promise((r) => setTimeout(r, 80));
    return fallback;
  }
  const res = await fetch(`/api${path}`, { credentials: "include" });
  if (!res.ok) {
    throw new Error(`AionUi: ${path} -> HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

/**
 * `api` — resource-scoped accessors. Prefer these over inline fetches
 * so the mock toggle and auth cookies are applied uniformly.
 */
export const api = {
  // ---- Dashboard / shared ------------------------------------------------
  dashboardKpis: () => get<Kpi[]>("/dashboard/kpis", mockKpis),
  eventStream: () => get<EventStreamEntry[]>("/dashboard/events", mockEvents),

  // ---- Assets / inventory ------------------------------------------------
  assets: () => get<Asset[]>("/assets", mockAssets),

  // ---- Vulnerabilities ---------------------------------------------------
  vulnerabilities: () =>
    get<Vulnerability[]>("/vulnerabilities", mockVulnerabilities),

  // ---- Incidents ---------------------------------------------------------
  incidents: () => get<Incident[]>("/incidents", mockIncidents),

  // ---- SBOM (Sprint 1 stub; Sprint 2 detail) -----------------------------
  /** Sprint 1 lightweight list — kept for backwards compatibility. */
  sbom: () => get<SbomComponentEnhanced[]>("/sbom/components", mockSbomFull),
  /** Sprint 2 full SBOM document for the viewer. */
  sbomDocument: (id: string) =>
    get<SbomDocument>(`/sbom/${encodeURIComponent(id)}`, mockSbomDocument),
  /** CycloneDX export URL — pages use this directly with a temporary <a>. */
  sbomExportUrl: (id: string, format: "cyclonedx-1.5" | "spdx-2.3" = "cyclonedx-1.5") =>
    USE_MOCKS
      ? `data:application/json,${encodeURIComponent(JSON.stringify(mockSbomDocument, null, 2))}`
      : `/api/sbom/${encodeURIComponent(id)}/export?format=${format}`,

  // ---- Compliance --------------------------------------------------------
  compliance: () =>
    get<ComplianceControl[]>("/compliance/controls", mockCompliance),

  // ---- Integrations ------------------------------------------------------
  integrations: () =>
    get<Integration[]>("/integrations", mockIntegrations),

  // ---- Sprint 2 — Security visualizations (S2.5 contracts) ---------------
  /** Composite security score with sub-metrics + sparklines. */
  securityScore: () =>
    get<SecurityScore>("/security/score", mockSecurityScore),

  /** Vulnerability timeline, parameterized by date range. */
  vulnTimeline: (range: VulnTimelineRange) =>
    get<VulnTimelinePoint[]>(
      `/security/vuln-timeline?range=${range}`,
      mockVulnTimeline(range)
    ),

  /** Ecosystem × severity risk heatmap. */
  riskHeatmap: () =>
    get<RiskHeatmap>("/security/risk-heatmap", mockRiskHeatmap),

  /** Dependency graph payload for a given SBOM id. */
  graphData: (sbomId: string) =>
    get<GraphData>(
      `/security/graph/${encodeURIComponent(sbomId)}`,
      mockGraphData(sbomId)
    ),

  // ---- Sprint 4 — Infrastructure intelligence -----------------------
  /** Onboarded clusters. */
  kubernetesClusters: () =>
    get<{ items: Cluster[]; total: number }>(
      "/kubernetes/clusters",
      { items: mockClusters, total: mockClusters.length },
    ),
  kubernetesNamespaces: (clusterId?: string) =>
    get<{ items: Namespace[]; total: number }>(
      clusterId
        ? `/kubernetes/namespaces?clusterId=${clusterId}`
        : "/kubernetes/namespaces",
      { items: mockNamespaces, total: mockNamespaces.length },
    ),
  kubernetesWorkloads: (clusterId?: string, namespace?: string) =>
    get<{ items: Workload[]; total: number }>(
      `/kubernetes/workloads?${new URLSearchParams({ ...(clusterId ? { clusterId } : {}), ...(namespace ? { namespace } : {}) }).toString()}`,
      { items: mockWorkloads, total: mockWorkloads.length },
    ),
  kubernetesPods: (clusterId?: string, namespace?: string) =>
    get<{ items: Pod[]; total: number }>(
      `/kubernetes/pods?${new URLSearchParams({ ...(clusterId ? { clusterId } : {}), ...(namespace ? { namespace } : {}) }).toString()}`,
      { items: mockPods, total: mockPods.length },
    ),
  kubernetesServices: (clusterId?: string) =>
    get<{ items: K8sService[]; total: number }>(
      clusterId
        ? `/kubernetes/services?clusterId=${clusterId}`
        : "/kubernetes/services",
      { items: mockServices, total: mockServices.length },
    ),
  kubernetesDeployments: (clusterId?: string) =>
    get<{ items: Deployment[]; total: number }>(
      clusterId
        ? `/kubernetes/deployments?clusterId=${clusterId}`
        : "/kubernetes/deployments",
      { items: mockDeployments, total: mockDeployments.length },
    ),
  kubernetesIngresses: (clusterId?: string) =>
    get<{ items: Ingress[]; total: number }>(
      clusterId
        ? `/kubernetes/ingresses?clusterId=${clusterId}`
        : "/kubernetes/ingresses",
      { items: mockIngresses, total: mockIngresses.length },
    ),

  // ---- K8s health ---------------------------------------------------
  healthClusters: () =>
    get<{ items: InfrastructureHealth[]; total: number }>(
      "/k8s-health/clusters",
      { items: mockHealth.filter((h) => h.scope === "cluster"), total: mockHealth.filter((h) => h.scope === "cluster").length },
    ),
  healthNamespaces: () =>
    get<{ items: InfrastructureHealth[]; total: number }>(
      "/k8s-health/namespaces",
      { items: [], total: 0 },
    ),
  healthWorkloads: () =>
    get<{ items: InfrastructureHealth[]; total: number }>(
      "/k8s-health/workloads",
      { items: [], total: 0 },
    ),
  healthPods: () =>
    get<{ items: InfrastructureHealth[]; total: number }>(
      "/k8s-health/pods",
      { items: [], total: 0 },
    ),
  healthRecommendations: () =>
    get<{ items: InfrastructureHealth["recommendations"]; total: number }>(
      "/k8s-health/recommendations",
      { items: mockHealth[0]?.recommendations ?? [], total: mockHealth[0]?.recommendations.length ?? 0 },
    ),
  healthIssues: () =>
    get<{ items: InfrastructureHealth["issues"]; total: number }>(
      "/k8s-health/issues",
      { items: mockHealth[0]?.issues ?? [], total: mockHealth[0]?.issues.length ?? 0 },
    ),

  // ---- Runtime security -------------------------------------------
  runtimeRisks: () =>
    get<{ items: RuntimeRisk[]; total: number }>(
      "/runtime-security/risks",
      { items: mockRuntimeRisks, total: mockRuntimeRisks.length },
    ),
  runtimeReport: () =>
    get<{ items: RuntimeSecurityReport[]; total: number }>(
      "/runtime-security/report",
      { items: [mockRuntimeReport], total: 1 },
    ),

  // ---- Cost intelligence -----------------------------------------
  costAnalysis: () =>
    get<{ items: CostAnalysis[]; total: number }>(
      "/cost/analysis",
      { items: [mockCostAnalysis], total: 1 },
    ),
  costWorkloads: () =>
    get<{ items: WorkloadCost[]; total: number }>(
      "/cost/workloads",
      { items: mockWorkloadCosts, total: mockWorkloadCosts.length },
    ),
  costFindings: () =>
    get<{ items: CostFinding[]; total: number }>(
      "/cost/findings",
      { items: mockCostFindings, total: mockCostFindings.length },
    ),
  costRecommendations: () =>
    get<{ items: CostRecommendation[]; total: number }>(
      "/cost/recommendations",
      { items: mockCostRecommendations, total: mockCostRecommendations.length },
    ),

  // ---- Topology ---------------------------------------------------
  topologyGraphs: () =>
    get<{ items: TopologyGraph[]; total: number }>(
      "/topology/graphs",
      { items: [mockTopologyGraph], total: 1 },
    ),
  topologyServiceMap: () =>
    get<TopologyGraph>("/topology/service-map", mockTopologyGraph),
  topologyApplicationGraph: () =>
    get<TopologyGraph>("/topology/application-graph", mockTopologyGraph),

  // ---- Inventory --------------------------------------------------
  inventoryAssets: () =>
    get<{ items: Asset[]; total: number }>(
      "/inventory/assets",
      { items: mockAssets, total: mockAssets.length },
    ),
};
