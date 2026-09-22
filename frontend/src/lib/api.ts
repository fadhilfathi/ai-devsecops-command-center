/**
 * Thin, typed API client used by every AionUi page.
 *
 * In Sprint 1 the client returned mock data from `lib/mock.ts`. In
 * Sprint 2 we add the security endpoints (S2.5) and the graph/SBOM
 * detail endpoints. The `USE_MOCKS` toggle lets pages render before
 * the S2.5 API is deployed.
 */

import { useSyncExternalStore } from 'react';
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
  Severity,
  VulnTimelinePoint,
  VulnTimelineRange,
  Vulnerability,
} from '@/types';
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
} from '@/types/infrastructure';
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
} from './mock';
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
} from './infrastructure.mock';

// Mocks stay the default so the app renders with no backend running; set
// VITE_USE_MOCKS=false to hit the real services (see frontend/README.md).
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false';
// Dev-only shortcut until S6-2 lands real auth — every service requires
// this header and rejects requests without it.
const TENANT_ID = import.meta.env.VITE_TENANT_ID ?? 'demo-tenant';

// ---- Degraded-mode tracking (S6-1) ---------------------------------------
// When mocks are off and a real request fails, `get()` still returns the
// mock fallback (a page must never crash), but records the failure here so
// the app shell can show a persistent "showing sample data" banner instead
// of failing silently.
export type ApiHealthState = { degraded: boolean; failures: string[] };

let healthState: ApiHealthState = { degraded: false, failures: [] };
const healthListeners = new Set<() => void>();

function recordFailure(path: string): void {
  if (healthState.failures.includes(path)) return;
  healthState = { degraded: true, failures: [...healthState.failures, path] };
  for (const listener of healthListeners) listener();
}

export const apiHealth = {
  get: (): ApiHealthState => healthState,
  subscribe: (listener: () => void): (() => void) => {
    healthListeners.add(listener);
    return () => healthListeners.delete(listener);
  },
  /** Test-only reset; not used by app code. */
  reset: (): void => {
    healthState = { degraded: false, failures: [] };
  },
};

/** React hook for the degraded-mode banner (AppShell/StatusBar). */
export function useApiHealth(): ApiHealthState {
  return useSyncExternalStore(apiHealth.subscribe, apiHealth.get);
}

/**
 * Fetch `path`, apply `transform` to the raw JSON, and fall back to
 * `fallback` on any error (mocks on, mock-only endpoint, non-2xx, or thrown
 * error) — recording the failure in `apiHealth` unless mocks are on.
 */
async function getRaw<Raw, T>(
  path: string,
  fallback: T,
  transform: (raw: Raw) => T,
  opts: { mockOnly?: boolean } = {},
): Promise<T> {
  if (USE_MOCKS || opts.mockOnly) {
    // Simulate a small network delay so loading states are exercised.
    await new Promise((r) => setTimeout(r, 80));
    return fallback;
  }
  try {
    const res = await fetch(`/api${path}`, {
      credentials: 'include',
      headers: { 'x-tenant-id': TENANT_ID },
    });
    if (!res.ok) {
      console.warn(`AionUi: ${path} -> HTTP ${res.status}, using fallback`);
      recordFailure(path);
      return fallback;
    }
    return transform((await res.json()) as Raw);
  } catch (err) {
    console.warn(`AionUi: ${path} -> request failed, using fallback`, err);
    recordFailure(path);
    return fallback;
  }
}

function get<T>(path: string, fallback: T, opts: { mockOnly?: boolean } = {}): Promise<T> {
  return getRaw<T, T>(path, fallback, (raw) => raw, opts);
}

// ---- Security dashboard aggregate -> dashboard KPIs / event stream -------
// security-service exposes one aggregate (`/security/dashboard`); the
// Sprint 1 dashboard screen wants two separate shapes, so both accessors
// hit the same endpoint and reshape the response locally.
type SecurityDashboardRaw = {
  sbomCount: number;
  totalVulnCount: number;
  vulnCountBySeverity: { critical: number; high: number; medium: number; low: number };
  securityScore: number;
  securityScoreTrend: { date: string; score: number }[];
  recentActivity: { id: string; timestamp: string; summary: string; severity: string }[];
};

function dashboardToKpis(d: SecurityDashboardRaw): Kpi[] {
  const trend = d.securityScoreTrend;
  const prevScore = trend.length > 1 ? trend[trend.length - 2]!.score : d.securityScore;
  const delta = prevScore === 0 ? 0 : Math.round(((d.securityScore - prevScore) / prevScore) * 100);
  return [
    {
      label: 'Security Score',
      value: String(d.securityScore),
      delta,
      trend: d.securityScore === prevScore ? 'flat' : d.securityScore > prevScore ? 'up' : 'down',
    },
    { label: 'Open Vulnerabilities', value: String(d.totalVulnCount) },
    { label: 'Critical Findings', value: String(d.vulnCountBySeverity.critical) },
    { label: 'SBOMs Tracked', value: String(d.sbomCount) },
  ];
}

const KNOWN_SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function dashboardToEvents(d: SecurityDashboardRaw): EventStreamEntry[] {
  return d.recentActivity.map((entry) => ({
    id: entry.id,
    ts: entry.timestamp,
    source: 'system',
    level: (KNOWN_SEVERITIES as readonly string[]).includes(entry.severity)
      ? (entry.severity as Severity)
      : 'info',
    message: entry.summary,
  }));
}

/**
 * `api` — resource-scoped accessors. Prefer these over inline fetches
 * so the mock toggle and auth cookies are applied uniformly.
 */
export const api = {
  // ---- Dashboard / shared ------------------------------------------------
  // Both reshape security-service's `/security/dashboard` aggregate — see
  // dashboardToKpis/dashboardToEvents above.
  dashboardKpis: () =>
    getRaw<SecurityDashboardRaw, Kpi[]>('/security/dashboard', mockKpis, dashboardToKpis),
  eventStream: () =>
    getRaw<SecurityDashboardRaw, EventStreamEntry[]>(
      '/security/dashboard',
      mockEvents,
      dashboardToEvents,
    ),

  // ---- Assets / inventory ------------------------------------------------
  assets: () => get<Asset[]>('/assets', mockAssets),

  // ---- Vulnerabilities ---------------------------------------------------
  // ponytail: no backend route yet (S6-1) — security-service has no GET
  // /vulnerabilities (findings are listed via /v1/findings, a different
  // shape); mock-only until that's wired up.
  vulnerabilities: () =>
    get<Vulnerability[]>('/vulnerabilities', mockVulnerabilities, { mockOnly: true }),

  // ---- Incidents ---------------------------------------------------------
  incidents: () => get<Incident[]>('/incidents', mockIncidents),

  // ---- SBOM (Sprint 1 stub; Sprint 2 detail) -----------------------------
  // ponytail: no backend route yet (S6-1) — mock-only until a components
  // listing endpoint exists.
  /** Sprint 1 lightweight list — kept for backwards compatibility. */
  sbom: () => get<SbomComponentEnhanced[]>('/sbom/components', mockSbomFull, { mockOnly: true }),
  /** Sprint 2 full SBOM document for the viewer. */
  sbomDocument: (id: string) =>
    get<SbomDocument>(`/sboms/${encodeURIComponent(id)}`, mockSbomDocument),
  /** CycloneDX export URL — pages use this directly with a temporary <a>. */
  // ponytail: security-service has no /v1/sboms/:id/export route yet, so the
  // export button always serves the locally held document as a data: URL.
  sbomExportUrl: (_id: string, _format: 'cyclonedx-1.5' | 'spdx-2.3' = 'cyclonedx-1.5') =>
    `data:application/json,${encodeURIComponent(JSON.stringify(mockSbomDocument, null, 2))}`,

  // ---- Compliance --------------------------------------------------------
  compliance: () => get<ComplianceControl[]>('/controls', mockCompliance),

  // ---- Integrations ------------------------------------------------------
  integrations: () => get<Integration[]>('/integrations', mockIntegrations),

  // ---- Sprint 2 — Security visualizations (S2.5 contracts) ---------------
  // ponytail: no backend route yet (S6-1) — mock-only for all four below.
  /** Composite security score with sub-metrics + sparklines. */
  securityScore: () => get<SecurityScore>('/security/score', mockSecurityScore, { mockOnly: true }),

  /** Vulnerability timeline, parameterized by date range. */
  vulnTimeline: (range: VulnTimelineRange) =>
    get<VulnTimelinePoint[]>(`/security/vuln-timeline?range=${range}`, mockVulnTimeline(range), {
      mockOnly: true,
    }),

  /** Ecosystem × severity risk heatmap. */
  riskHeatmap: () =>
    get<RiskHeatmap>('/security/risk-heatmap', mockRiskHeatmap, { mockOnly: true }),

  /** Dependency graph payload for a given SBOM id. */
  graphData: (sbomId: string) =>
    get<GraphData>(`/security/graph/${encodeURIComponent(sbomId)}`, mockGraphData(sbomId), {
      mockOnly: true,
    }),

  // ---- Sprint 4 — Infrastructure intelligence -----------------------
  /** Onboarded clusters. */
  kubernetesClusters: () =>
    get<{ items: Cluster[]; total: number }>('/clusters', {
      items: mockClusters,
      total: mockClusters.length,
    }),
  kubernetesNamespaces: (clusterId?: string) =>
    get<{ items: Namespace[]; total: number }>(
      clusterId ? `/namespaces?clusterId=${clusterId}` : '/namespaces',
      { items: mockNamespaces, total: mockNamespaces.length },
    ),
  kubernetesWorkloads: (clusterId?: string, namespace?: string) =>
    get<{ items: Workload[]; total: number }>(
      `/workloads?${new URLSearchParams({ ...(clusterId ? { clusterId } : {}), ...(namespace ? { namespace } : {}) }).toString()}`,
      { items: mockWorkloads, total: mockWorkloads.length },
    ),
  kubernetesPods: (clusterId?: string, namespace?: string) =>
    get<{ items: Pod[]; total: number }>(
      `/pods?${new URLSearchParams({ ...(clusterId ? { clusterId } : {}), ...(namespace ? { namespace } : {}) }).toString()}`,
      { items: mockPods, total: mockPods.length },
    ),
  kubernetesServices: (clusterId?: string) =>
    get<{ items: K8sService[]; total: number }>(
      clusterId ? `/services?clusterId=${clusterId}` : '/services',
      { items: mockServices, total: mockServices.length },
    ),
  kubernetesDeployments: (clusterId?: string) =>
    get<{ items: Deployment[]; total: number }>(
      clusterId ? `/deployments?clusterId=${clusterId}` : '/deployments',
      { items: mockDeployments, total: mockDeployments.length },
    ),
  kubernetesIngresses: (clusterId?: string) =>
    get<{ items: Ingress[]; total: number }>(
      clusterId ? `/ingresses?clusterId=${clusterId}` : '/ingresses',
      { items: mockIngresses, total: mockIngresses.length },
    ),

  // ---- K8s health ---------------------------------------------------
  healthClusters: () =>
    get<{ items: InfrastructureHealth[]; total: number }>('/health/clusters', {
      items: mockHealth.filter((h) => h.scope === 'cluster'),
      total: mockHealth.filter((h) => h.scope === 'cluster').length,
    }),
  healthNamespaces: () =>
    get<{ items: InfrastructureHealth[]; total: number }>('/health/namespaces', {
      items: [],
      total: 0,
    }),
  healthWorkloads: () =>
    get<{ items: InfrastructureHealth[]; total: number }>('/health/workloads', {
      items: [],
      total: 0,
    }),
  healthPods: () =>
    get<{ items: InfrastructureHealth[]; total: number }>('/health/pods', {
      items: [],
      total: 0,
    }),
  healthRecommendations: () =>
    get<{ items: InfrastructureHealth['recommendations']; total: number }>(
      '/health/recommendations',
      {
        items: mockHealth[0]?.recommendations ?? [],
        total: mockHealth[0]?.recommendations.length ?? 0,
      },
    ),
  healthIssues: () =>
    get<{ items: InfrastructureHealth['issues']; total: number }>('/health/issues', {
      items: mockHealth[0]?.issues ?? [],
      total: mockHealth[0]?.issues.length ?? 0,
    }),

  // ---- Runtime security -------------------------------------------
  runtimeRisks: () =>
    get<{ items: RuntimeRisk[]; total: number }>('/runtime-security/risks', {
      items: mockRuntimeRisks,
      total: mockRuntimeRisks.length,
    }),
  runtimeReport: () =>
    get<{ items: RuntimeSecurityReport[]; total: number }>('/runtime-security/report', {
      items: [mockRuntimeReport],
      total: 1,
    }),

  // ---- Cost intelligence -----------------------------------------
  costAnalysis: () =>
    get<{ items: CostAnalysis[]; total: number }>('/cost/analysis', {
      items: [mockCostAnalysis],
      total: 1,
    }),
  costWorkloads: () =>
    get<{ items: WorkloadCost[]; total: number }>('/cost/workloads', {
      items: mockWorkloadCosts,
      total: mockWorkloadCosts.length,
    }),
  costFindings: () =>
    get<{ items: CostFinding[]; total: number }>('/cost/findings', {
      items: mockCostFindings,
      total: mockCostFindings.length,
    }),
  costRecommendations: () =>
    get<{ items: CostRecommendation[]; total: number }>('/cost/recommendations', {
      items: mockCostRecommendations,
      total: mockCostRecommendations.length,
    }),

  // ---- Topology ---------------------------------------------------
  topologyGraphs: () =>
    get<{ items: TopologyGraph[]; total: number }>('/topology/graphs', {
      items: [mockTopologyGraph],
      total: 1,
    }),
  topologyServiceMap: () => get<TopologyGraph>('/topology/service-map', mockTopologyGraph),
  topologyApplicationGraph: () =>
    get<TopologyGraph>('/topology/application-graph', mockTopologyGraph),

  // ---- Inventory --------------------------------------------------
  inventoryAssets: () =>
    get<{ items: Asset[]; total: number }>('/inventory/assets', {
      items: mockAssets,
      total: mockAssets.length,
    }),
};
