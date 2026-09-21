/**
 * Mock data for AionUi screens.
 *
 * Sprint 1: shapes match the shared types in `@/types` and mirror what
 * the backend services were expected to return.
 *
 * Sprint 2: adds security mocks consumed by the 5 S2.6 visualizations.
 * They match the S2.5 API contract exactly, so flipping
 * `USE_MOCKS = false` in `lib/api.ts` switches the UI to live data
 * with no caller changes.
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
  RiskHeatmapCell,
  SbomComponentEnhanced,
  SbomDocument,
  SecurityScore,
  VulnTimelinePoint,
  VulnTimelineRange,
  Vulnerability,
  Ecosystem,
  Severity,
} from "@/types";

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

const now = () => new Date().toISOString();
const ago = (mins: number) =>
  new Date(Date.now() - mins * 60_000).toISOString();

/** Seeded pseudo-random — keeps mock data stable across reloads. */
function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(0xa10c);

// -------------------------------------------------------------------------
// Sprint 1 mocks
// -------------------------------------------------------------------------

export const mockKpis: Kpi[] = [
  {
    label: "Open Critical Vulns",
    value: "7",
    delta: -12,
    trend: "down",
    hint: "vs. last 7 days",
  },
  {
    label: "Active Incidents",
    value: "3",
    delta: +1,
    trend: "up",
    hint: "1 P1, 2 P3",
  },
  {
    label: "Managed Assets",
    value: "1,284",
    delta: +18,
    trend: "up",
    hint: "across 4 environments",
  },
  {
    label: "Compliance Score",
    value: "92%",
    delta: +1.4,
    trend: "up",
    hint: "CISv8 · 187/203 controls",
  },
  {
    label: "MTTR (security)",
    value: "4h 12m",
    delta: -22,
    trend: "down",
    hint: "median over 30d",
  },
  {
    label: "SBOM Coverage",
    value: "98%",
    delta: +0.4,
    trend: "flat",
    hint: "1,259 / 1,284 assets",
  },
];

export const mockEvents: EventStreamEntry[] = [
  { id: "evt-1001", ts: ago(0.5), source: "agent", level: "high",
    message: "Dependency-Agent detected CVE-2024-3094 in service:checkout-api" },
  { id: "evt-1002", ts: ago(2),   source: "github", level: "info",
    message: "PR #2841 opened: bump xz-utils to 5.4.2 (auto-remediation)" },
  { id: "evt-1003", ts: ago(5),   source: "siem",   level: "critical",
    message: "Anomalous IAM role assumption in prod/aws-account-7421" },
  { id: "evt-1004", ts: ago(8),   source: "system", level: "low",
    message: "Daily CISv8 evidence collection completed (187 controls)" },
  { id: "evt-1005", ts: ago(14),  source: "agent",  level: "medium",
    message: "SBOM drift detected: 3 new transitive deps in order-service" },
  { id: "evt-1006", ts: ago(22),  source: "user",   level: "info",
    message: "m.chen accepted risk for CVE-2023-45878 (compensating control)" },
  { id: "evt-1007", ts: ago(41),  source: "agent",  level: "high",
    message: "Secret-Agent: AWS access key leaked in public gist" },
  { id: "evt-1008", ts: ago(63),  source: "github", level: "info",
    message: "Status check 'aion/policy' succeeded on main @ a1b2c3d" },
];

export const mockAssets: Asset[] = [
  { id: "ast-001", name: "checkout-api", kind: "service", owner: "team:payments",
    environment: "prod", criticality: "critical", lastSeen: ago(1),
    tags: ["node", "pci-scope", "public-internet"] },
  { id: "ast-002", name: "web-app", kind: "repository", owner: "team:web",
    environment: "prod", criticality: "high", lastSeen: ago(4),
    tags: ["react", "monorepo"] },
  { id: "ast-003", name: "aion-gateway", kind: "container", owner: "team:platform",
    environment: "prod", criticality: "critical", lastSeen: ago(0.3),
    tags: ["go", "istio"] },
  { id: "ast-004", name: "warehouse-prod", kind: "data-store", owner: "team:data",
    environment: "prod", criticality: "high", lastSeen: ago(11),
    tags: ["snowflake", "pci-scope"] },
  { id: "ast-005", name: "ci-runner-pool", kind: "service", owner: "team:devops",
    environment: "prod", criticality: "medium", lastSeen: ago(2),
    tags: ["github-actions"] },
  { id: "ast-006", name: "okta-tenant-acme", kind: "identity", owner: "team:it",
    environment: "prod", criticality: "critical", lastSeen: ago(0.1),
    tags: ["sso", "scim"] },
  { id: "ast-007", name: "marketing-site", kind: "repository", owner: "team:marketing",
    environment: "staging", criticality: "low", lastSeen: ago(120),
    tags: ["nextjs"] },
  { id: "ast-008", name: "sandbox-rds", kind: "data-store", owner: "team:platform",
    environment: "sandbox", criticality: "info", lastSeen: ago(900),
    tags: ["postgres"] },
];

export const mockVulnerabilities: Vulnerability[] = [
  { id: "vuln-501", cve: "CVE-2024-3094", title: "xz-utils backdoor (supply-chain compromise)",
    severity: "critical", cvss: 10.0, package: "xz-utils", version: "5.6.0",
    fixedIn: "5.6.1", status: "in-progress", assetId: "ast-001", detectedAt: ago(60) },
  { id: "vuln-502", cve: "CVE-2024-21626", title: "runc file descriptor leak (container escape)",
    severity: "critical", cvss: 9.8, package: "runc", version: "1.1.11",
    fixedIn: "1.1.12", status: "open", assetId: "ast-003", detectedAt: ago(180) },
  { id: "vuln-503", cve: "CVE-2023-44487", title: "HTTP/2 Rapid Reset (DoS)",
    severity: "high", cvss: 7.5, package: "envoy", version: "1.28.0",
    fixedIn: "1.29.1", status: "triaged", assetId: "ast-003", detectedAt: ago(720) },
  { id: "vuln-504", cve: "CVE-2023-45878", title: "MiniZip integer overflow",
    severity: "medium", cvss: 6.5, package: "minizip", version: "1.2.13",
    fixedIn: "1.3.0", status: "accepted", assetId: "ast-002", detectedAt: ago(4320) },
  { id: "vuln-505", title: "Outdated base image (debian:bullseye)",
    severity: "medium", cvss: 5.4, package: "debian:bullseye", version: "20240130",
    fixedIn: "debian:bookworm", status: "open", assetId: "ast-005", detectedAt: ago(60 * 24 * 3) },
  { id: "vuln-506", cve: "CVE-2024-2389", title: "OpenSSL use-after-free",
    severity: "high", cvss: 7.2, package: "openssl", version: "3.0.11",
    fixedIn: "3.0.13", status: "remediated", assetId: "ast-001", detectedAt: ago(60 * 24 * 5) },
  { id: "vuln-507", title: "Hardcoded credential in source",
    severity: "low", cvss: 3.7, package: "internal-payments-sdk", version: "0.4.2",
    status: "in-progress", assetId: "ast-002", detectedAt: ago(60 * 24 * 2) },
];

export const mockIncidents: Incident[] = [
  { id: "inc-9001", title: "Suspicious IAM role chain in prod", severity: "critical",
    status: "investigating", assignee: "m.chen", source: "siem",
    createdAt: ago(15), updatedAt: ago(2),
    summary: "Anomalous sts:AssumeRole observed from a new region; isolating affected principals." },
  { id: "inc-9002", title: "CI runner token exposed in public log", severity: "high",
    status: "contained", assignee: "r.patel", source: "agent",
    createdAt: ago(180), updatedAt: ago(40),
    summary: "GitHub Actions logs revealed a long-lived PAT. Token revoked, runner re-imaged." },
  { id: "inc-9003", title: "Dependency confusion attempt blocked", severity: "medium",
    status: "resolved", assignee: "a.kowalski", source: "agent",
    createdAt: ago(60 * 12), updatedAt: ago(60 * 10),
    summary: "Sentinel-Agent blocked an internal-looking package from a typo-squatted registry." },
  { id: "inc-9004", title: "CIS control 5.4 regression on prod", severity: "low",
    status: "open", assignee: "unassigned", source: "system",
    createdAt: ago(60 * 30), updatedAt: ago(60 * 30),
    summary: "MFA enforcement drifted on 2 service accounts; auto-remediation queued." },
];

export const mockCompliance: ComplianceControl[] = [
  { id: "c-1", family: "CIS 1 — Inventory", framework: "CISv8",
    title: "Establish and Maintain Detailed Enterprise Asset Inventory",
    status: "pass", evidenceCount: 14, lastAssessedAt: ago(60 * 5) },
  { id: "c-2", family: "CIS 5 — Access Control", framework: "CISv8",
    title: "MFA for All Administrative Access", status: "pass",
    evidenceCount: 9, lastAssessedAt: ago(60 * 4) },
  { id: "c-3", family: "CIS 5 — Access Control", framework: "CISv8",
    title: "Disable Dormant Accounts within 60 Days", status: "partial",
    evidenceCount: 4, lastAssessedAt: ago(60 * 9) },
  { id: "c-4", family: "CIS 7 — Vulnerability Mgmt", framework: "CISv8",
    title: "Automated Vulnerability Scanning of Internal Assets",
    status: "pass", evidenceCount: 22, lastAssessedAt: ago(60 * 2) },
  { id: "c-5", family: "CIS 16 — App Security", framework: "CISv8",
    title: "Establish and Maintain a Process to Accept and Manage SBOMs",
    status: "partial", evidenceCount: 3, lastAssessedAt: ago(60 * 8) },
  { id: "c-6", family: "NIST AC-02", framework: "NIST-800-53",
    title: "Account Management", status: "pass", evidenceCount: 11,
    lastAssessedAt: ago(60 * 12) },
  { id: "c-7", family: "NIST SI-04", framework: "NIST-800-53",
    title: "Information System Monitoring", status: "fail",
    evidenceCount: 1, lastAssessedAt: ago(60 * 30) },
  { id: "c-8", family: "NIST RA-05", framework: "NIST-800-53",
    title: "Vulnerability Monitoring & Scanning", status: "pass",
    evidenceCount: 18, lastAssessedAt: ago(60 * 6) },
];

export const mockIntegrations: Integration[] = [
  { id: "int-1", name: "GitHub Enterprise", category: "scm", vendor: "GitHub",
    status: "connected", lastSyncAt: ago(1) },
  { id: "int-2", name: "GitLab.com", category: "scm", vendor: "GitLab",
    status: "disconnected" },
  { id: "int-3", name: "GitHub Actions", category: "ci", vendor: "GitHub",
    status: "connected", lastSyncAt: ago(0.5) },
  { id: "int-4", name: "Jira Cloud", category: "ticketing", vendor: "Atlassian",
    status: "connected", lastSyncAt: ago(4) },
  { id: "int-5", name: "Slack Workspace", category: "chat", vendor: "Slack",
    status: "needs-attention", lastSyncAt: ago(60 * 36) },
  { id: "int-6", name: "AWS Organization", category: "cloud", vendor: "Amazon",
    status: "connected", lastSyncAt: ago(6) },
  { id: "int-7", name: "Google Cloud", category: "cloud", vendor: "Google",
    status: "connected", lastSyncAt: ago(22) },
  { id: "int-8", name: "Splunk Cloud", category: "siem", vendor: "Splunk",
    status: "connected", lastSyncAt: ago(0.7) },
  { id: "int-9", name: "Okta Workforce", category: "iam", vendor: "Okta",
    status: "connected", lastSyncAt: ago(0.1) },
  { id: "int-10", name: "PagerDuty", category: "chat", vendor: "PagerDuty",
    status: "connected", lastSyncAt: ago(2) },
];

// -------------------------------------------------------------------------
// Sprint 2 — Security mocks (S2.5 API contract)
// -------------------------------------------------------------------------

// ---- SBOM ----------------------------------------------------------------

const ECOSYSTEMS: Ecosystem[] = [
  "npm", "pypi", "maven", "go", "rubygems", "cargo", "nuget", "other",
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const COMMON_PACKAGES: Record<Ecosystem, string[]> = {
  npm: ["react", "lodash", "axios", "express", "next", "@types/node", "typescript",
    "tailwindcss", "vite", "recharts", "zod", "react-router-dom"],
  pypi: ["django", "requests", "flask", "fastapi", "sqlalchemy", "celery",
    "pydantic", "numpy", "pandas", "urllib3", "cryptography"],
  maven: ["org.springframework:spring-core", "com.fasterxml.jackson.core:jackson-databind",
    "org.apache.commons:commons-lang3", "ch.qos.logback:logback-classic",
    "org.slf4j:slf4j-api", "junit:junit"],
  go: ["github.com/gin-gonic/gin", "github.com/labstack/echo/v4",
    "github.com/spf13/cobra", "github.com/stretchr/testify",
    "golang.org/x/crypto", "github.com/go-redis/redis/v9"],
  rubygems: ["rails", "puma", "nokogiri", "sidekiq", "devise", "pg"],
  cargo: ["serde", "tokio", "reqwest", "actix-web", "clap", "rustls"],
  nuget: ["Newtonsoft.Json", "Microsoft.AspNetCore", "Serilog", "xunit", "Moq"],
  other: ["openssl", "libcurl", "zlib", "sqlite"],
};

const COMMON_LICENSES = [
  "MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0", "MPL-2.0", "Unlicense",
];

/** Generate a stable, deterministic SBOM component list. */
function generateSbomComponents(seed: number, count: number): SbomComponentEnhanced[] {
  const r = mulberry32(seed);
  const out: SbomComponentEnhanced[] = [];
  for (let i = 0; i < count; i++) {
    const eco = ECOSYSTEMS[Math.floor(r() * ECOSYSTEMS.length)];
    const pkgs = COMMON_PACKAGES[eco];
    const name = pkgs[Math.floor(r() * pkgs.length)];
    const versionMajor = 1 + Math.floor(r() * 8);
    const versionMinor = Math.floor(r() * 12);
    const versionPatch = Math.floor(r() * 20);
    const depth = Math.floor(r() * 4); // 0..3
    const vulnRoll = r();
    let highestSeverity: Severity | undefined;
    if (vulnRoll > 0.85) highestSeverity = "critical";
    else if (vulnRoll > 0.7) highestSeverity = "high";
    else if (vulnRoll > 0.5) highestSeverity = "medium";
    else if (vulnRoll > 0.4) highestSeverity = "low";
    out.push({
      id: `cmp-${i.toString().padStart(4, "0")}`,
      name,
      version: `${versionMajor}.${versionMinor}.${versionPatch}`,
      purl: `pkg:${eco}/${name}@${versionMajor}.${versionMinor}.${versionPatch}`,
      license: COMMON_LICENSES[Math.floor(r() * COMMON_LICENSES.length)],
      supplier: undefined,
      ecosystem: eco,
      depth,
      vulnerabilities:
        highestSeverity === "critical" ? 1 + Math.floor(r() * 3)
        : highestSeverity === "high"     ? Math.floor(r() * 3)
        : highestSeverity === "medium"   ? Math.floor(r() * 2)
        : highestSeverity === "low"      ? Math.floor(r() * 2)
        : 0,
      highestSeverity,
    });
  }
  return out;
}

/** Lightweight list used by Sprint-1 /sbom route body. */
export const mockSbomFull: SbomComponentEnhanced[] =
  generateSbomComponents(0xa10c, 64);

/** Full SBOM document for the Sprint-2 viewer. */
export const mockSbomDocument: SbomDocument = {
  id: "sbom-checkout-api-2026-06-12",
  assetId: "ast-001",
  assetName: "checkout-api",
  generatedAt: ago(30),
  format: "CycloneDX-1.5",
  componentCount: 124,
  components: generateSbomComponents(0xa10c, 124),
};

// ---- Vulnerability timeline ---------------------------------------------

function buildTimeline(range: VulnTimelineRange): VulnTimelinePoint[] {
  const days = range === "7d" ? 7 : range === "30d" ? 30 : range === "90d" ? 90 : 52;
  const useWeeks = range === "1y";
  const points: VulnTimelinePoint[] = [];
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    if (useWeeks) d.setDate(d.getDate() - i * 7);
    else d.setDate(d.getDate() - i);
    const label = useWeeks
      ? `W${Math.floor((days - 1 - i))}`
      : d.toISOString().slice(0, 10);
    // Stable-ish values that trend mildly downward (improvement).
    const t = (days - i) / days;
    const noise = (n: number) => 0.7 + (rand() - 0.5) * 0.6 + n;
    points.push({
      date: label,
      critical: Math.max(0, Math.round(noise(0.3) * (1.0 - t * 0.3))),
      high:     Math.max(0, Math.round(noise(1.2) * (1.0 - t * 0.2))),
      medium:   Math.max(0, Math.round(noise(3.0) * (1.0 - t * 0.15))),
      low:      Math.max(0, Math.round(noise(2.0) * (1.0 - t * 0.1))),
      info:     Math.max(0, Math.round(noise(0.6))),
    });
  }
  return points;
}

export const mockVulnTimeline = (range: VulnTimelineRange): VulnTimelinePoint[] =>
  buildTimeline(range);

// ---- Risk heatmap --------------------------------------------------------

function buildRiskHeatmap(): RiskHeatmap {
  const cells: RiskHeatmapCell[] = [];
  let totalVulns = 0;
  // Realistic-looking distribution: npm is the largest, "other" the smallest.
  const ecosystemVolume: Record<Ecosystem, number> = {
    npm: 1.0, pypi: 0.7, maven: 0.55, go: 0.45,
    rubygems: 0.3, cargo: 0.25, nuget: 0.35, other: 0.2,
  };
  const severityVolume: Record<Severity, number> = {
    critical: 0.06, high: 0.18, medium: 0.42, low: 0.24, info: 0.10,
  };
  for (const eco of ECOSYSTEMS) {
    for (const sev of SEVERITIES) {
      const base = 24 * ecosystemVolume[eco] * severityVolume[sev];
      const count = Math.max(0, Math.round(base + (rand() - 0.5) * 6));
      cells.push({ ecosystem: eco, severity: sev, count });
      totalVulns += count;
    }
  }
  return {
    cells,
    ecosystems: ECOSYSTEMS,
    totalVulns,
    generatedAt: now(),
  };
}

export const mockRiskHeatmap: RiskHeatmap = buildRiskHeatmap();

// ---- Security score ------------------------------------------------------

function spark(seed: number, base: number, variance: number, n = 14): number[] {
  const r = mulberry32(seed);
  const out: number[] = [];
  for (let i = 0; i < n; i++) out.push(Math.max(0, base + (r() - 0.5) * variance));
  return out;
}

export const mockSecurityScore: SecurityScore = {
  composite: 87,
  band: "B",
  generatedAt: now(),
  subMetrics: [
    {
      id: "sbom-coverage",
      label: "SBOM coverage",
      value: 98,
      format: "percent",
      betterWhen: "higher",
      hint: "1,259 / 1,284 assets",
      sparkline: spark(0x501, 96, 4),
      delta: 0.4,
    },
    {
      id: "critical-vulns",
      label: "Critical vulns",
      value: 7,
      format: "count",
      betterWhen: "lower",
      hint: "open across the estate",
      sparkline: spark(0x502, 9, 5),
      delta: -12,
    },
    {
      id: "mttr",
      label: "MTTR (security)",
      value: 252, // minutes
      format: "duration",
      betterWhen: "lower",
      hint: "median over 30d",
      sparkline: spark(0x503, 320, 80),
      delta: -22,
    },
    {
      id: "kev-exposure",
      label: "KEV exposure",
      value: 2,
      format: "count",
      betterWhen: "lower",
      hint: "assets with CISA KEV CVEs",
      sparkline: spark(0x504, 3, 1.4),
      delta: 0,
    },
    {
      id: "epss-avg",
      label: "EPSS (avg)",
      value: 18,
      format: "percent",
      betterWhen: "lower",
      hint: "exploit-likelihood score",
      sparkline: spark(0x505, 22, 6),
      delta: -3.1,
    },
  ],
};

// ---- Dependency graph ----------------------------------------------------

function buildGraphData(sbomId: string): GraphData {
  const comps = generateSbomComponents(0xa10c, 28);
  const nodes: GraphData["nodes"] = comps.map((c) => ({
    id: c.id,
    label: c.name,
    ecosystem: c.ecosystem,
    depth: c.depth,
    vulnCount: c.vulnerabilities,
    highestSeverity: c.highestSeverity,
    version: c.version,
  }));
  const edges: GraphData["edges"] = [];
  // Wire each transitive node to a random shallower node (parent).
  for (const n of nodes) {
    if (n.depth === 0) continue;
    const candidates = nodes.filter((p) => p.depth < n.depth);
    if (candidates.length === 0) continue;
    const parent = candidates[Math.floor(rand() * candidates.length)];
    edges.push({ source: parent.id, target: n.id });
  }
  return { sbomId, nodes, edges };
}

export const mockGraphData = (sbomId: string): GraphData => buildGraphData(sbomId);

// Quiet "unused" warnings on `now` and `ago` while keeping them available
// for future mock expansion.
void now;
