/**
 * Shared TypeScript types used across the AionUi frontend.
 *
 * These mirror the contracts published by the six backend services
 * (auth, agent, security, incident, compliance, integration). When
 * the API gateway emits OpenAPI, we can codegen these from it.
 *
 * Sprint 2 adds the security types consumed by the S2.5 API layer
 * and rendered by the 5 visualizations in S2.6.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AssetKind =
  | "repository"
  | "service"
  | "container"
  | "identity"
  | "data-store"
  | "saas-account";

export type Asset = {
  id: string;
  name: string;
  kind: AssetKind;
  owner: string;
  environment: "prod" | "staging" | "dev" | "sandbox";
  criticality: Severity;
  lastSeen: string; // ISO
  tags: string[];
};

export type Vulnerability = {
  id: string; // CVE-XXXX-XXXXX or internal ID
  cve?: string;
  title: string;
  severity: Severity;
  cvss: number;
  package: string;
  version: string;
  fixedIn?: string;
  status: "open" | "triaged" | "in-progress" | "remediated" | "accepted";
  assetId: string;
  detectedAt: string;
};

export type Incident = {
  id: string;
  title: string;
  severity: Severity;
  status: "open" | "investigating" | "contained" | "resolved" | "postmortem";
  assignee: string;
  source: "github" | "siem" | "agent" | "user" | "cloud";
  createdAt: string;
  updatedAt: string;
  summary: string;
};

export type SbomComponent = {
  id: string;
  name: string;
  version: string;
  purl: string; // package URL
  license: string;
  supplier?: string;
  vulnerabilities: number;
};

export type ComplianceControl = {
  id: string;
  family: string; // e.g. "CIS 5 — Access Control"
  framework: "CISv8" | "NIST-800-53" | "SOC2" | "ISO-27001";
  title: string;
  status: "pass" | "fail" | "partial" | "not-assessed";
  evidenceCount: number;
  lastAssessedAt: string;
};

export type Integration = {
  id: string;
  name: string;
  category: "scm" | "ci" | "ticketing" | "chat" | "cloud" | "siem" | "iam";
  vendor: string;
  status: "connected" | "needs-attention" | "disconnected";
  lastSyncAt?: string;
};

export type Kpi = {
  label: string;
  value: string;
  delta?: number; // percent
  trend?: "up" | "down" | "flat";
  hint?: string;
};

export type EventStreamEntry = {
  id: string;
  ts: string;
  source: "agent" | "github" | "siem" | "system" | "user";
  level: Severity;
  message: string;
};

// -------------------------------------------------------------------------
// Sprint 2 — Security types (S2.5 contracts; consumed by S2.6 visualizations)
// -------------------------------------------------------------------------

/** Package ecosystems recognized by the SBOM pipeline (Syft-derived). */
export type Ecosystem =
  | "npm"
  | "pypi"
  | "maven"
  | "go"
  | "rubygems"
  | "cargo"
  | "nuget"
  | "other";

/** An enriched SBOM component, used by the SBOM Viewer and the graph. */
export type SbomComponentEnhanced = SbomComponent & {
  ecosystem: Ecosystem;
  depth: number; // 0 = direct, 1+ = transitive
  highestSeverity?: Severity;
};

/** A complete SBOM document, addressed by asset / sbom id. */
export type SbomDocument = {
  id: string;
  assetId: string;
  assetName: string;
  generatedAt: string;
  format: "CycloneDX-1.5" | "SPDX-2.3";
  componentCount: number;
  components: SbomComponentEnhanced[];
};

/** One point on the vulnerability timeline (one day). */
export type VulnTimelinePoint = {
  date: string; // YYYY-MM-DD
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

/** Date range for the vulnerability timeline. */
export type VulnTimelineRange = "7d" | "30d" | "90d" | "1y";

/** One cell of the risk heatmap. */
export type RiskHeatmapCell = {
  ecosystem: Ecosystem;
  severity: Severity;
  count: number;
};

/** The full risk heatmap for a snapshot. */
export type RiskHeatmap = {
  cells: RiskHeatmapCell[];
  ecosystems: Ecosystem[];
  totalVulns: number;
  generatedAt: string;
};

/** A sub-metric on the Security Score card. */
export type SecurityScoreSubMetric = {
  id: string;
  label: string;
  /** For "percent" / "score" / "duration" — interpret per `format`. */
  value: number;
  /** How to render `value` on the tile. */
  format: "percent" | "count" | "duration" | "score";
  /** Direction the metric should be trending (used to color deltas). */
  betterWhen: "higher" | "lower";
  /** Optional sub-label / hint. */
  hint?: string;
  /** Recent values for the sparkline (oldest first). */
  sparkline: number[];
  /** Optional delta vs. previous period (percent). */
  delta?: number;
};

/** Composite security score + sub-metrics. */
export type SecurityScore = {
  /** 0..100 composite. */
  composite: number;
  /** Letter band derived from the composite. */
  band: "A" | "B" | "C" | "D" | "F";
  subMetrics: SecurityScoreSubMetric[];
  generatedAt: string;
};

/** A node in the dependency graph. */
export type GraphNode = {
  id: string;
  label: string;
  ecosystem: Ecosystem;
  depth: number;
  vulnCount: number;
  highestSeverity?: Severity;
  version: string;
};

/** An edge in the dependency graph: source depends on target. */
export type GraphEdge = {
  source: string;
  target: string;
};

/** Dependency graph payload (server-side, layout computed client-side). */
export type GraphData = {
  sbomId: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
};
