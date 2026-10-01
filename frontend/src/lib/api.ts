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
  AgentFinding,
  AgentTaskEnvelope,
  ApplyInput,
  ApplyResult,
  Asset,
  ComplianceControl,
  EventStreamEntry,
  GraphData,
  Incident,
  Integration,
  Kpi,
  RemediationEcosystem,
  RemediationFinding,
  RemediationResult,
  RiskHeatmap,
  SbomDocument,
  SecurityScore,
  SbomComponentEnhanced,
  Severity,
  TriageFinding,
  TriageResult,
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
  mockApplyResult,
  mockAssets,
  mockCompliance,
  mockEvents,
  mockGraphData,
  mockIncidents,
  mockIntegrations,
  mockKpis,
  mockRemediationResult,
  mockRiskHeatmap,
  mockSbomDocument,
  mockSbomFull,
  mockSecurityScore,
  mockTriageResult,
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
import { getToken, isAuthRequired, sessionExpired } from './auth';

// Mocks stay the default so the app renders with no backend running; set
// VITE_USE_MOCKS=false to hit the real services (see frontend/README.md).
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false';
// Legacy dev fallback: sent only when logged out (see `getRaw` below) —
// every service accepts it while AUTH_DEV_BYPASS is on (dev/test default).
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
  // A previous request already 401'd — the app shell shows the login gate;
  // don't keep hammering the backend with the stale x-tenant-id fallback.
  if (isAuthRequired()) {
    return fallback;
  }
  try {
    const token = getToken();
    // Prefer a real bearer token; fall back to the legacy tenant header
    // (matches every service's AUTH_DEV_BYPASS dev/test default) only
    // before the first login attempt — keeps the app usable before S6-2's
    // login screen without silently retrying it after a 401.
    const headers: Record<string, string> = token
      ? { authorization: `Bearer ${token}` }
      : { 'x-tenant-id': TENANT_ID };
    const res = await fetch(`/api${path}`, { credentials: 'include', headers });
    if (res.status === 401) {
      sessionExpired();
    }
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

// ---- Agent triage / remediation tasks (S11-3) ----------------------------

/**
 * Derive a package ecosystem from a package name.
 *
 * The frontend `Vulnerability` wire type carries no ecosystem field (the
 * SBOM types do), but both agent-service task inputs require one — so we
 * derive a best-effort guess from the name:
 *   - `@scope/name`        → npm (scoped npm packages)
 *   - slash-separated path → go (module path, e.g. github.com/org/repo)
 *   - `group:artifact`     → maven coordinates
 *   - PascalCase           → nuget (Newtonsoft.Json, Microsoft.Extensions.*)
 *   - contains `.` or `_`  → pypi (PEP 503 distribution names)
 *   - anything else        → npm — bare npm, cargo and (some) pypi names are
 *                            indistinguishable, so fall back to the largest
 *                            ecosystem in the estate.
 */
export function deriveEcosystem(packageName: string): RemediationEcosystem {
  const name = packageName.trim();
  if (name.startsWith('@')) return 'npm';
  if (name.includes('/')) return 'go';
  if (name.includes(':')) return 'maven';
  if (/^[A-Z]/.test(name)) return 'nuget';
  if (/[._]/.test(name)) return 'pypi';
  return 'npm';
}

/**
 * Map a frontend `Vulnerability` onto the agent-service finding input
 * shared by `triage.findings` and `remediation.propose` (`AgentFinding`).
 * One helper for both call sites so the wire mapping lives in exactly one
 * place.
 *
 * Backend scoring fields derivable from `Vulnerability`: `cvss` (carried
 * through) and `fixAvailable` (a fix exists iff `fixedIn` is set — the
 * triage heuristic penalizes `fixAvailable: false`, so leaving it unset
 * would silently score unfixable findings as fixable). `kev`, `epss`,
 * `assetCriticality` and `exposure` are genuinely NOT derivable from
 * `Vulnerability` and stay unset — do not invent derivations for them.
 */
export function toAgentFinding(v: Vulnerability): AgentFinding {
  return {
    id: v.id,
    cveId: v.cve,
    package: { name: v.package, ecosystem: deriveEcosystem(v.package), version: v.version },
    fixedVersions: v.fixedIn ? [v.fixedIn] : [],
    fixAvailable: Boolean(v.fixedIn),
    cvss: v.cvss,
    // The frontend `Severity` spells info-level `info`; the agent spells it
    // `informational`.
    severity: v.severity === 'info' ? 'informational' : v.severity,
  };
}

/** Strict JSON request shared by the agent-task POST and its poll GET:
 * same auth headers and 401 `sessionExpired()` / `recordFailure()`
 * behaviour as `getRaw`, but it throws on failure instead of substituting
 * a fallback. */
async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  // A previous request already 401'd — don't keep hammering the backend
  // with the stale x-tenant-id fallback.
  if (isAuthRequired()) {
    throw new Error('Log in to run agent tasks.');
  }
  const token = getToken();
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : { 'x-tenant-id': TENANT_ID }),
  };
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, credentials: 'include', headers });
  } catch (err) {
    console.warn(`AionUi: ${path} -> request failed`, err);
    recordFailure(path);
    throw new Error('Request failed — is the backend running?');
  }
  if (res.status === 401) {
    sessionExpired();
  }
  if (!res.ok) {
    console.warn(`AionUi: ${path} -> HTTP ${res.status}`);
    recordFailure(path);
    throw new Error(`Request failed (HTTP ${res.status}).`);
  }
  return (await res.json()) as T;
}

const TASK_POLL_INTERVAL_MS = 500;
const TASK_POLL_MAX = 20;

/**
 * POST helper (sibling of `get`/`getRaw`) for agent tasks — same
 * mock-switch (fixture + 80ms delay), 401 `sessionExpired()` and
 * `recordFailure()` behaviour. Submits `kind` to POST /agents/tasks, polls
 * GET /agents/tasks/:id (500ms × ≤20 — never hangs past the cap) until the
 * task settles, and returns its `result`. In mock mode the fixture is
 * returned without touching the network. Throws on live failure: a task
 * run must surface its error, never resolve to sample data.
 */
async function postAgentTask<R>(
  kind: string,
  payload: Record<string, unknown>,
  mock: R,
): Promise<R> {
  if (USE_MOCKS) {
    await new Promise((r) => setTimeout(r, 80));
    return mock;
  }
  const created = await requestJson<AgentTaskEnvelope>('/agents/tasks', {
    method: 'POST',
    body: JSON.stringify({ kind, payload }),
  });
  for (let poll = 0; poll < TASK_POLL_MAX; poll++) {
    await new Promise((r) => setTimeout(r, TASK_POLL_INTERVAL_MS));
    const { task } = await requestJson<AgentTaskEnvelope>(
      `/agents/tasks/${encodeURIComponent(created.task.id)}`,
    );
    if (task.status === 'completed') return task.result as R;
    if (task.status === 'failed' || task.status === 'cancelled') {
      throw new Error(task.error ?? `Agent task ${kind} ${task.status}.`);
    }
  }
  throw new Error(`Agent task ${kind} timed out after ${TASK_POLL_MAX} polls.`);
}

// ---- SBOM export download (S9-2) ------------------------------------------
type SbomExportFormat = 'cyclonedx-1.5' | 'spdx-2.3';

/** Thrown by `downloadSbom` on any export failure in live mode (mocks off).
 * A page must never silently substitute mock content for a real export
 * failure — the caller shows `message` inline instead. */
export class SbomExportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SbomExportError';
  }
}

/** Thrown when the stored SBOM can't be served in the requested format
 * (security-service's `/v1/sboms/:id/export` 501s). */
export class SbomExportUnsupportedError extends SbomExportError {
  constructor(message: string) {
    super(message);
    this.name = 'SbomExportUnsupportedError';
  }
}

function extFor(format: SbomExportFormat): string {
  return format === 'cyclonedx-1.5' ? 'cyclonedx.json' : 'spdx.json';
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Defer the revoke past the click handler so the browser has started
  // reading the blob URL before it's invalidated.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function downloadMockSbom(id: string, format: SbomExportFormat): void {
  const blob = new Blob([JSON.stringify(mockSbomDocument, null, 2)], {
    type: 'application/json',
  });
  triggerDownload(blob, `sbom-${id}.${extFor(format)}`);
}

/** Extracts the raw (still unsanitized) filename from a `Content-Disposition`
 * header — RFC 5987 `filename*=UTF-8''...` preferred, then quoted/unquoted
 * `filename=`. */
function extractFilename(disposition: string): string | null {
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(disposition);
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      // malformed percent-encoding — fall through to the other patterns.
    }
  }
  const quoted = /filename\s*=\s*"([^"]*)"/i.exec(disposition);
  if (quoted) return quoted[1]!;
  const unquoted = /filename\s*=\s*([^;]+)/i.exec(disposition);
  if (unquoted) return unquoted[1]!.trim();
  return null;
}

/** Builds a filesystem-safe download filename from a `Content-Disposition`
 * header, or `fallback` if the header is missing/empty/unsafe. Guards
 * against path traversal and injected control/separator characters — the
 * header is attacker-influenced (it round-trips through the export
 * request). */
export function safeDownloadFilename(disposition: string, fallback: string): string {
  const raw = extractFilename(disposition);
  if (!raw) return fallback;
  // Basename only — drop any path prefix the header tried to smuggle in,
  // Windows and POSIX separators both.
  const base = raw.split(/[/\\]/).pop() ?? '';
  const safe = base
    // eslint-disable-next-line no-control-regex -- intentionally stripping control chars
    .replace(/[\u0000-\u001f\u007f]/g, '') // control chars
    .replace(/\.\./g, '') // traversal sequences
    .replace(/[^A-Za-z0-9._-]/g, '_') // restrict charset
    .slice(0, 100);
  return safe || fallback;
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
  // security-service's `/v1/vulnerabilities` (S8-4) returns `{ items, total }`.
  vulnerabilities: () =>
    getRaw<{ items: Vulnerability[] }, Vulnerability[]>(
      '/vulnerabilities',
      mockVulnerabilities,
      (raw) => raw.items,
    ),

  // ---- Sprint 11 — Triage & remediation (S11-3) --------------------------
  // Feed the rows of `vulnerabilities()` through `toAgentFinding` first.
  /** Score findings with the agent (`triage.findings` task). */
  triageFindings: (findings: TriageFinding[]): Promise<TriageResult> =>
    postAgentTask<TriageResult>('triage.findings', { findings }, mockTriageResult),

  /** Generate dependency-bump proposals (`remediation.propose` task). */
  remediationProposals: (findings: RemediationFinding[]): Promise<RemediationResult> =>
    postAgentTask<RemediationResult>('remediation.propose', { findings }, mockRemediationResult),

  /** Apply a proposal via integration-service (`remediation.apply` task). */
  applyRemediation: (input: ApplyInput): Promise<ApplyResult> =>
    postAgentTask<ApplyResult>('remediation.apply', { ...input }, mockApplyResult),

  // ---- Incidents ---------------------------------------------------------
  incidents: () => get<Incident[]>('/incidents', mockIncidents),

  // ---- SBOM (Sprint 1 stub; Sprint 2 detail) -----------------------------
  /** Sprint 1 lightweight list — kept for backwards compatibility. Backed
   * by security-service's `/v1/sbom/components` (S8-4). */
  sbom: () =>
    getRaw<{ items: SbomComponentEnhanced[] }, SbomComponentEnhanced[]>(
      '/sbom/components',
      mockSbomFull,
      (raw) => raw.items,
    ),
  /** Sprint 2 full SBOM document for the viewer. */
  sbomDocument: (id: string) =>
    get<SbomDocument>(`/sboms/${encodeURIComponent(id)}`, mockSbomDocument),
  /** Download the CycloneDX/SPDX export of an SBOM. With mocks on, downloads
   * the mock document. In live mode a failed export NEVER falls back to
   * mock content — it throws `SbomExportUnsupportedError` (501, stored
   * format differs from `format`) or the base `SbomExportError` (any other
   * failure), marking the API degraded like `get()` does; the caller shows
   * the message inline. */
  downloadSbom: async (id: string, format: SbomExportFormat = 'cyclonedx-1.5'): Promise<void> => {
    if (USE_MOCKS) {
      downloadMockSbom(id, format);
      return;
    }
    if (isAuthRequired()) {
      throw new SbomExportError('Log in to export this SBOM.');
    }
    const path = `/sboms/${encodeURIComponent(id)}/export?format=${format}`;
    try {
      const token = getToken();
      const headers: Record<string, string> = token
        ? { authorization: `Bearer ${token}` }
        : { 'x-tenant-id': TENANT_ID };
      const res = await fetch(`/api${path}`, { credentials: 'include', headers });
      if (res.status === 401) {
        sessionExpired();
      }
      if (res.status === 501) {
        const body = (await res.json().catch(() => null)) as { message?: string } | null;
        throw new SbomExportUnsupportedError(
          body?.message ?? 'This SBOM is stored in another format',
        );
      }
      if (!res.ok) {
        console.warn(`AionUi: ${path} -> HTTP ${res.status}`);
        recordFailure(path);
        throw new SbomExportError('Failed to export this SBOM. Try again later.');
      }
      const blob = await res.blob();
      const disposition = res.headers.get('content-disposition') ?? '';
      const filename = safeDownloadFilename(disposition, `sbom-${id}.${extFor(format)}`);
      triggerDownload(blob, filename);
    } catch (err) {
      if (err instanceof SbomExportError) throw err;
      console.warn(`AionUi: ${path} -> request failed`, err);
      recordFailure(path);
      throw new SbomExportError('Failed to export this SBOM. Try again later.');
    }
  },

  // ---- Compliance --------------------------------------------------------
  compliance: () => get<ComplianceControl[]>('/controls', mockCompliance),

  // ---- Integrations ------------------------------------------------------
  integrations: () => get<Integration[]>('/integrations', mockIntegrations),

  // ---- Sprint 2 — Security visualizations (S2.5 contracts; S8-4 wiring) --
  /** Composite security score with sub-metrics + sparklines. */
  securityScore: () => get<SecurityScore>('/security/score', mockSecurityScore),

  /** Vulnerability timeline, parameterized by date range. */
  vulnTimeline: (range: VulnTimelineRange) =>
    get<VulnTimelinePoint[]>(`/security/vuln-timeline?range=${range}`, mockVulnTimeline(range)),

  /** Ecosystem × severity risk heatmap. */
  riskHeatmap: () => get<RiskHeatmap>('/security/risk-heatmap', mockRiskHeatmap),

  /** Dependency graph payload. `sbomId` is tenant-wide today (security-service
   * has no per-SBOM graph endpoint, S8-4) — it's echoed back on the response
   * and otherwise unused for filtering. */
  graphData: (sbomId: string) =>
    get<GraphData>(`/security/graph?sbomId=${encodeURIComponent(sbomId)}`, mockGraphData(sbomId)),

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
