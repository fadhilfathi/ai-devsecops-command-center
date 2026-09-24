/**
 * Pure aggregation functions for the S8-4 frontend analytics endpoints.
 *
 * Routes stay thin — all the joining/bucketing logic lives here so it can
 * be unit-tested over hand-built fixtures without spinning up Fastify.
 *
 * The response types below intentionally mirror the wire shapes in
 * `frontend/src/types/index.ts` (`Vulnerability`, `SbomComponentEnhanced`,
 * `SecurityScore`, `VulnTimelinePoint`, `RiskHeatmap`, `GraphData`). They
 * are duplicated rather than imported — this is a JSON wire contract
 * between two independently-versioned packages, not a shared TS type.
 */
import type { VulnerabilityFinding, SecurityScan, Asset, FindingSeverity } from '@aicc/shared';
import type { SbomRecord } from '../repositories/sbom.repository.js';

// ---------- wire types ----------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Ecosystem = 'npm' | 'pypi' | 'maven' | 'go' | 'rubygems' | 'cargo' | 'nuget' | 'other';

export const ECOSYSTEMS: readonly Ecosystem[] = [
  'npm',
  'pypi',
  'maven',
  'go',
  'rubygems',
  'cargo',
  'nuget',
  'other',
];

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface WireVulnerability {
  id: string;
  cve?: string;
  title: string;
  severity: Severity;
  cvss: number;
  package: string;
  version: string;
  fixedIn?: string;
  status: 'open' | 'triaged' | 'in-progress' | 'remediated' | 'accepted';
  assetId: string;
  detectedAt: string;
}

export interface WireSbomComponent {
  id: string;
  name: string;
  version: string;
  purl: string;
  license: string;
  supplier?: string;
  vulnerabilities: number;
  ecosystem: Ecosystem;
  depth: number;
  highestSeverity?: Severity;
}

export interface RiskHeatmapCell {
  ecosystem: Ecosystem;
  severity: Severity;
  count: number;
}

export interface RiskHeatmap {
  cells: RiskHeatmapCell[];
  ecosystems: Ecosystem[];
  totalVulns: number;
  generatedAt: string;
}

export interface SecurityScoreSubMetric {
  id: string;
  label: string;
  value: number;
  format: 'percent' | 'count' | 'duration' | 'score';
  betterWhen: 'higher' | 'lower';
  hint?: string;
  sparkline: number[];
  delta?: number;
}

/** Discriminated on `hasData` — `false` when the tenant has no assets,
 * SBOMs, or findings yet, so `composite`/`band` don't claim a misleading
 * "perfect score" for an empty tenant. */
export type SecurityScore =
  | {
      hasData: true;
      composite: number;
      band: 'A' | 'B' | 'C' | 'D' | 'F';
      subMetrics: SecurityScoreSubMetric[];
      generatedAt: string;
    }
  | {
      hasData: false;
      composite: null;
      band: null;
      subMetrics: SecurityScoreSubMetric[];
      generatedAt: string;
    };

export interface VulnTimelinePoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export type VulnTimelineRange = '7d' | '30d' | '90d' | '1y';

export interface GraphNode {
  id: string;
  label: string;
  ecosystem: Ecosystem;
  depth: number;
  vulnCount: number;
  highestSeverity?: Severity;
  version: string;
}

export interface GraphEdge {
  source: string;
  target: string;
}

export interface GraphData {
  sbomId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ---------- shared helpers ----------

/** Backend has a 6th bucket ('unknown'); the frontend contract has 5. */
export function severityFromBackend(sev: FindingSeverity): Severity {
  return sev === 'unknown' ? 'info' : sev;
}

const STATUS_MAP: Record<VulnerabilityFinding['status'], WireVulnerability['status']> = {
  open: 'open',
  triaging: 'triaged',
  in_progress: 'in-progress',
  resolved: 'remediated',
  suppressed: 'accepted',
};

/**
 * Heuristic severity -> representative CVSS score. Findings don't carry a
 * real CVSS score yet (that lands with the vuln-intel-service ingest
 * pipeline); this mirrors the midpoints already used by the dashboard
 * aggregate (`routes/dashboard.ts`) so the two surfaces agree.
 */
export function severityToCvss(sev: Severity): number {
  switch (sev) {
    case 'critical':
      return 9.5;
    case 'high':
      return 7.5;
    case 'medium':
      return 5.0;
    case 'low':
      return 2.5;
    case 'info':
      return 0.1;
  }
}

function severityRank(sev: Severity): number {
  return SEVERITIES.indexOf(sev);
}

/** CycloneDX purl "pkg:<type>/..." -> our coarser Ecosystem enum. */
export function ecosystemFromPurl(purl: string | undefined): Ecosystem {
  if (!purl) return 'other';
  const m = /^pkg:([a-zA-Z0-9.+-]+)\//.exec(purl);
  const type = m?.[1]?.toLowerCase();
  switch (type) {
    case 'npm':
      return 'npm';
    case 'pypi':
      return 'pypi';
    case 'maven':
      return 'maven';
    case 'golang':
      return 'go';
    case 'gem':
      return 'rubygems';
    case 'cargo':
      return 'cargo';
    case 'nuget':
      return 'nuget';
    default:
      return 'other';
  }
}

// ---------- CycloneDX-lite parsing (defensive; `document` is `unknown`) ----------

interface RawLicense {
  license?: { id?: string; name?: string };
  expression?: { expression?: string };
}

interface RawComponent {
  'bom-ref'?: string;
  name?: string;
  version?: string;
  purl?: string;
  licenses?: RawLicense[] | string[];
  supplier?: { name?: string } | string;
}

interface RawDependency {
  ref?: string;
  dependsOn?: string[];
}

interface RawSbomDocument {
  components?: RawComponent[];
  dependencies?: RawDependency[];
  metadata?: { component?: { 'bom-ref'?: string } };
}

function isRawSbomDocument(doc: unknown): doc is RawSbomDocument {
  return typeof doc === 'object' && doc !== null;
}

function licenseLabel(licenses: RawComponent['licenses']): string {
  const first = licenses?.[0];
  if (!first) return 'unknown';
  if (typeof first === 'string') return first;
  if (first.license?.id) return first.license.id;
  if (first.license?.name) return first.license.name;
  if (first.expression?.expression) return first.expression.expression;
  return 'unknown';
}

/**
 * Depth of every component's `bom-ref`, BFS from the document's root
 * component. 0 = direct dependency of the root, 1+ = transitive.
 *
 * ponytail: falls back to depth 0 for every component when the document
 * carries no `dependencies` graph (common for hand-authored demo SBOMs) —
 * upgrade to a real default once every SBOM is generated via the
 * sbom-pipeline-service, which always emits one.
 */
function computeDepths(doc: RawSbomDocument): Map<string, number> {
  const depths = new Map<string, number>();
  const root = doc.metadata?.component?.['bom-ref'];
  const deps = doc.dependencies ?? [];
  if (!root || deps.length === 0) return depths;

  const byRef = new Map<string, string[]>();
  for (const d of deps) {
    if (d.ref) byRef.set(d.ref, d.dependsOn ?? []);
  }
  const queue: Array<{ ref: string; depth: number }> = (byRef.get(root) ?? []).map((ref) => ({
    ref,
    depth: 0,
  }));
  const seen = new Set<string>();
  while (queue.length > 0) {
    const { ref, depth } = queue.shift()!;
    if (seen.has(ref)) continue;
    seen.add(ref);
    depths.set(ref, depth);
    for (const child of byRef.get(ref) ?? []) {
      if (!seen.has(child)) queue.push({ ref: child, depth: depth + 1 });
    }
  }
  return depths;
}

interface ParsedSbom {
  components: WireSbomComponent[];
  edges: GraphEdge[];
}

/** Parse one SBOM record into wire components + dependency edges, joined
 * against `findings` by package name (+ version when present). */
function parseSbomRecord(record: SbomRecord, findings: VulnerabilityFinding[]): ParsedSbom {
  const doc = isRawSbomDocument(record.document) ? record.document : {};
  const rawComponents = doc.components ?? [];
  const depths = computeDepths(doc);

  const findingsByPackage = new Map<string, VulnerabilityFinding[]>();
  for (const f of findings) {
    if (!f.packageName) continue;
    const key = f.packageName.toLowerCase();
    const list = findingsByPackage.get(key) ?? [];
    list.push(f);
    findingsByPackage.set(key, list);
  }

  const components: WireSbomComponent[] = rawComponents.map((c) => {
    const name = c.name ?? 'unknown';
    const version = c.version ?? '';
    const id = c['bom-ref'] ?? `${name}@${version || '*'}`;
    const matches = (findingsByPackage.get(name.toLowerCase()) ?? []).filter(
      (f) => !f.packageVersion || !version || f.packageVersion === version,
    );
    const highestSeverity = matches.reduce<Severity | undefined>((acc, f) => {
      const sev = severityFromBackend(f.severity);
      return acc === undefined || severityRank(sev) > severityRank(acc) ? sev : acc;
    }, undefined);
    return {
      id,
      name,
      version,
      purl: c.purl ?? '',
      license: licenseLabel(c.licenses),
      supplier: typeof c.supplier === 'string' ? c.supplier : (c.supplier?.name ?? undefined),
      vulnerabilities: matches.length,
      ecosystem: ecosystemFromPurl(c.purl),
      depth: depths.get(id) ?? 0,
      highestSeverity,
    };
  });

  // Edges reference `bom-ref`s directly; any edge touching a ref that
  // isn't a real component (e.g. the synthetic root) is dropped later in
  // `buildDependencyGraph`, once we know which ids made the node cut.
  const edges: GraphEdge[] = [];
  for (const d of doc.dependencies ?? []) {
    if (!d.ref) continue;
    for (const target of d.dependsOn ?? []) {
      edges.push({ source: d.ref, target });
    }
  }

  return { components, edges };
}

// ---------- public aggregations ----------

// ponytail: every call below re-parses every SBOM document the tenant owns
// on every request (components list, graph, heatmap) — ceiling is fine at
// demo/seed scale but degrades linearly with SBOM count and document size.
// Upgrade path: precompute WireSbomComponent[]/edges once at ingest time
// (`POST /v1/sboms`) and cache alongside the record, or cap parsing to the
// latest SBOM per asset instead of every historical one.

/** Flat component listing across every SBOM the tenant has, for the
 * "lightweight index" list view. */
export function extractSbomComponents(
  records: SbomRecord[],
  findings: VulnerabilityFinding[],
): WireSbomComponent[] {
  return records.flatMap((r) => parseSbomRecord(r, findings).components);
}

/**
 * Bounded dependency graph across every SBOM the tenant has. Capped at
 * `cap` nodes (default 50) to keep the reactflow canvas responsive;
 * vulnerable components are always kept first.
 */
export function buildDependencyGraph(
  records: SbomRecord[],
  findings: VulnerabilityFinding[],
  sbomId: string,
  cap = 50,
): GraphData {
  const parsed = records.map((r) => parseSbomRecord(r, findings));
  const allNodes = parsed.flatMap((p) => p.components);
  const allEdges = parsed.flatMap((p) => p.edges);

  // `severityRank` indexes into SEVERITIES (critical=0 .. info=4), so the
  // most severe components sort first with a plain ascending comparator.
  const ranked = [...allNodes].sort((a, b) => {
    const bySeverity =
      severityRank(a.highestSeverity ?? 'info') - severityRank(b.highestSeverity ?? 'info');
    if (bySeverity !== 0) return bySeverity;
    return a.depth - b.depth;
  });
  const kept = ranked.slice(0, cap);
  const keptIds = new Set(kept.map((n) => n.id));

  const nodes: GraphNode[] = kept.map((c) => ({
    id: c.id,
    label: c.name,
    ecosystem: c.ecosystem,
    depth: c.depth,
    vulnCount: c.vulnerabilities,
    highestSeverity: c.highestSeverity,
    version: c.version,
  }));
  const edges = allEdges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target));

  return { sbomId, nodes, edges };
}

/** Map every finding to the browser `Vulnerability` shape, joined through
 * `scans` to reach the originating asset. */
export function toWireVulnerabilities(
  findings: VulnerabilityFinding[],
  scans: SecurityScan[],
): WireVulnerability[] {
  const assetByScan = new Map(scans.map((s) => [s.id, s.assetId]));
  return findings.map((f) => {
    const sev = severityFromBackend(f.severity);
    return {
      id: f.id,
      cve: f.cveId,
      title: f.title,
      severity: sev,
      cvss: severityToCvss(sev),
      package: f.packageName ?? 'unknown',
      version: f.packageVersion ?? '',
      status: STATUS_MAP[f.status],
      assetId: assetByScan.get(f.scanId) ?? '',
      detectedAt: f.createdAt,
    };
  });
}

const OPEN_STATUSES: ReadonlySet<VulnerabilityFinding['status']> = new Set([
  'open',
  'triaging',
  'in_progress',
]);

/**
 * Composite security score (0-100) + sub-metrics.
 *
 * Formula (deterministic, mirrors `routes/dashboard.ts`'s heuristic):
 *   penalty  = critical*10 + high*5 + medium*2 + low*0.5   (open findings only)
 *   composite = clamp(round(100 - penalty), 0, 100)
 *   band      = A >=90, B >=75, C >=60, D >=40, else F
 *
 * No score history is persisted yet, so every sub-metric's `sparkline`
 * is a single point — the frontend renders a flat line rather than fake
 * trend data.
 */
export function computeSecurityScore(
  findings: VulnerabilityFinding[],
  assets: Asset[],
  sboms: SbomRecord[],
): SecurityScore {
  if (assets.length === 0 && sboms.length === 0 && findings.length === 0) {
    return {
      hasData: false,
      composite: null,
      band: null,
      subMetrics: [],
      generatedAt: new Date().toISOString(),
    };
  }

  const open = findings.filter((f) => OPEN_STATUSES.has(f.status));
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of open) {
    const sev = severityFromBackend(f.severity);
    if (sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low') {
      bySeverity[sev]++;
    }
  }
  const penalty =
    bySeverity.critical * 10 + bySeverity.high * 5 + bySeverity.medium * 2 + bySeverity.low * 0.5;
  const composite = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const band =
    composite >= 90
      ? 'A'
      : composite >= 75
        ? 'B'
        : composite >= 60
          ? 'C'
          : composite >= 40
            ? 'D'
            : 'F';

  const coveredAssetIds = new Set(sboms.map((s) => s.assetId));
  const sbomCoverage =
    assets.length === 0 ? 100 : Math.round((coveredAssetIds.size / assets.length) * 100);

  const now = Date.now();
  const ageDaysAvg =
    open.length === 0
      ? 0
      : open.reduce((sum, f) => sum + (now - new Date(f.createdAt).getTime()) / 86_400_000, 0) /
        open.length;

  const generatedAt = new Date().toISOString();
  const point = (v: number): number[] => [v];

  return {
    hasData: true,
    composite,
    band,
    generatedAt,
    subMetrics: [
      {
        id: 'sbom-coverage',
        label: 'SBOM coverage',
        value: sbomCoverage,
        format: 'percent',
        betterWhen: 'higher',
        hint: `${coveredAssetIds.size} / ${assets.length} assets`,
        sparkline: point(sbomCoverage),
      },
      {
        id: 'critical-vulns',
        label: 'Critical vulns',
        value: bySeverity.critical,
        format: 'count',
        betterWhen: 'lower',
        hint: 'open across the estate',
        sparkline: point(bySeverity.critical),
      },
      {
        id: 'open-vulns',
        label: 'Open vulnerabilities',
        value: open.length,
        format: 'count',
        betterWhen: 'lower',
        hint: 'open + triaging + in-progress',
        sparkline: point(open.length),
      },
      {
        id: 'avg-open-age',
        label: 'Avg. open finding age',
        value: Math.round(ageDaysAvg * 1440), // days -> minutes, matches the 'duration' format
        format: 'duration',
        betterWhen: 'lower',
        hint: 'mean age of currently-open findings',
        sparkline: point(Math.round(ageDaysAvg * 1440)),
      },
    ],
  };
}

/** Per-day open-finding counts by severity, over `range`. */
export function computeVulnTimeline(
  findings: VulnerabilityFinding[],
  range: VulnTimelineRange,
): VulnTimelinePoint[] {
  const days = range === '7d' ? 7 : range === '30d' ? 30 : range === '90d' ? 90 : 365;
  const byDay = new Map<string, VulnTimelinePoint>();
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - i);
    const date = d.toISOString().slice(0, 10);
    byDay.set(date, { date, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  }
  for (const f of findings) {
    const date = f.createdAt.slice(0, 10);
    const point = byDay.get(date);
    if (!point) continue; // outside the requested range
    point[severityFromBackend(f.severity)]++;
  }
  return Array.from(byDay.values());
}

/** Ecosystem x severity finding counts, ecosystem derived by joining each
 * finding's package name against the tenant's SBOM components. */
export function computeRiskHeatmap(
  findings: VulnerabilityFinding[],
  components: WireSbomComponent[],
): RiskHeatmap {
  const ecosystemByPackage = new Map<string, Ecosystem>();
  for (const c of components) {
    ecosystemByPackage.set(c.name.toLowerCase(), c.ecosystem);
  }

  const counts = new Map<string, number>();
  for (const eco of ECOSYSTEMS) {
    for (const sev of SEVERITIES) counts.set(`${eco}:${sev}`, 0);
  }
  for (const f of findings) {
    const eco = f.packageName
      ? (ecosystemByPackage.get(f.packageName.toLowerCase()) ?? 'other')
      : 'other';
    const sev = severityFromBackend(f.severity);
    const key = `${eco}:${sev}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const cells: RiskHeatmapCell[] = [];
  for (const eco of ECOSYSTEMS) {
    for (const sev of SEVERITIES) {
      cells.push({ ecosystem: eco, severity: sev, count: counts.get(`${eco}:${sev}`) ?? 0 });
    }
  }

  return {
    cells,
    ecosystems: [...ECOSYSTEMS],
    totalVulns: findings.length,
    generatedAt: new Date().toISOString(),
  };
}
