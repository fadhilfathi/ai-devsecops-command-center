/**
 * Risk-score model — composite 0-100 score for components, SBOMs, and vulnerabilities.
 *
 * Round-trips with the Python Pydantic model maintained by
 * VulnerabilityIntelligenceAgent (S2.3).
 *
 * Composite formula (default weights):
 *   score = round( 100 *
 *     ( 0.35 * severity
 *     + 0.20 * epss
 *     + 0.20 * kev
 *     + 0.15 * reachability
 *     + 0.10 * exposure ) )
 *
 * Each factor is normalised to 0..1 upstream:
 *   - severity:  (cvssBaseScore / 10)
 *   - epss:      EPSS score
 *   - kev:       1.0 if KEV, else 0.0
 *   - reachability: 1.0 (direct import), 0.5 (transitive, imported), 0.1 (transitive, not imported), 0.0 (no code path)
 *   - exposure:  1.0 (internet-facing), 0.7 (internal network), 0.3 (no network), 0.0 (dev/test)
 *
 * Higher score = riskier.
 */
import { z } from 'zod';

// ---------- factor breakdown (shared with dependency-graph.model.ts) ----------

export const RiskFactorBreakdownSchema = z.object({
  /** 0..1 — normalised severity (cvss / 10) */
  severity: z.number().min(0).max(1),
  /** 0..1 — EPSS exploit prediction probability */
  epss: z.number().min(0).max(1),
  /** 0..1 — CISA KEV flag (1.0 if listed, else 0.0) */
  kev: z.number().min(0).max(1),
  /** 0..1 — code reachability */
  reachability: z.number().min(0).max(1),
  /** 0..1 — network/internet exposure */
  exposure: z.number().min(0).max(1),
});
export type RiskFactorBreakdown = z.infer<typeof RiskFactorBreakdownSchema>;

export const RiskFactorWeightsSchema = z.object({
  severity: z.number().min(0).max(1),
  epss: z.number().min(0).max(1),
  kev: z.number().min(0).max(1),
  reachability: z.number().min(0).max(1),
  exposure: z.number().min(0).max(1),
}).refine((w) => {
  const sum = w.severity + w.epss + w.kev + w.reachability + w.exposure;
  return Math.abs(sum - 1) < 0.001;
}, { message: 'factor weights must sum to 1.0' });
export type RiskFactorWeights = z.infer<typeof RiskFactorWeightsSchema>;

/** Default weights used if `factorWeights` is not provided. */
export const DEFAULT_RISK_FACTOR_WEIGHTS: RiskFactorWeights = {
  severity: 0.35,
  epss: 0.20,
  kev: 0.20,
  reachability: 0.15,
  exposure: 0.10,
};

// ---------- subject identification ----------

export const RiskSubjectKindSchema = z.enum(['component', 'sbom', 'vulnerability', 'tenant']);
export type RiskSubjectKind = z.infer<typeof RiskSubjectKindSchema>;

export const RiskSubjectSchema = z.object({
  kind: RiskSubjectKindSchema,
  /** Component: `bom-ref`. SBOM: `serialNumber` (urn:uuid) or graphId. Vulnerability: `cve_id`/`ghsa_id`. */
  id: z.string().min(1),
  /** Human label for dashboards (component name, SBOM name, etc.) */
  label: z.string().optional(),
});
export type RiskSubject = z.infer<typeof RiskSubjectSchema>;

// ---------- top-level RiskScore ----------

export const RiskScoreSchema = z.object({
  subject: RiskSubjectSchema,
  /** Composite 0-100 score (integer, higher = riskier) */
  compositeScore: z.number().int().min(0).max(100),
  factors: RiskFactorBreakdownSchema,
  /** Weights used to compute the score (echoed for auditability) */
  factorWeights: RiskFactorWeightsSchema,
  /** Human-readable explanation, max 2000 chars */
  rationale: z.string().min(1).max(2000),
  /** When the score was computed */
  computedAt: z.string().datetime({ offset: true }),
  /** Model version that produced this score (e.g. `risk-score-v1`) */
  modelVersion: z.string().min(1).default('risk-score-v1'),
  /** Tenant this score belongs to (multi-tenant isolation) */
  tenantId: z.string().uuid().optional(),
}).passthrough();
export type RiskScore = z.infer<typeof RiskScoreSchema>;

// ---------- helpers ----------

/**
 * Pure function: compute a composite risk score from a factor breakdown.
 * Used by both the security-service proxy (S2.5) and unit tests.
 * Exported here so it can be shared with downstream consumers that
 * need to recompute on the TS side.
 */
export function computeCompositeScore(
  factors: RiskFactorBreakdown,
  weights: RiskFactorWeights = DEFAULT_RISK_FACTOR_WEIGHTS,
): number {
  const raw =
    weights.severity * factors.severity +
    weights.epss * factors.epss +
    weights.kev * factors.kev +
    weights.reachability * factors.reachability +
    weights.exposure * factors.exposure;
  return Math.round(Math.min(1, Math.max(0, raw)) * 100);
}

// ---------- service I/O shapes (used by S2.5 security-service dashboard) ----------

/**
 * Top 5 riskiest components — used by the `GET /security/dashboard` aggregate.
 * Source: dependency-intel-service's `NodeRiskWeight[]`, sorted by `weight` desc.
 */
export const TopRiskyComponentSchema = z.object({
  /** Component `bom-ref` */
  bomRef: z.string().min(1),
  name: z.string().min(1),
  version: z.string().optional(),
  /** Composite risk score 0-100 */
  score: z.number().int().min(0).max(100),
  /** Most severe CVE id (if any) */
  topVulnerabilityId: z.string().optional(),
  /** Top vulnerability CVSS base score (if known) */
  topCvssScore: z.number().min(0).max(10).optional(),
  /** EPSS percentile 0-1 (if known) */
  epssPercentile: z.number().min(0).max(1).optional(),
  /** Whether the component is in CISA KEV */
  kev: z.boolean().default(false),
});
export type TopRiskyComponent = z.infer<typeof TopRiskyComponentSchema>;

/** Recent activity event — surfaced in the dashboard. */
export const RecentActivityEntrySchema = z.object({
  id: z.string().uuid(),
  type: z.enum([
    'sbom.generated',
    'sbom.analyzed',
    'vulnerability.detected',
    'vulnerability.ingested',
    'risk.calculated',
    'scan.completed',
    'incident.created',
  ]),
  /** When the event happened */
  timestamp: z.string().datetime({ offset: true }),
  /** One-line human summary */
  summary: z.string().min(1).max(280),
  /** Optional deep link target */
  href: z.string().optional(),
  /** Optional severity colour hint for the UI */
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
  /** Tenant id */
  tenantId: z.string().uuid().optional(),
});
export type RecentActivityEntry = z.infer<typeof RecentActivityEntrySchema>;

/**
 * Response body for `GET /security/dashboard`.
 */
export const SecurityDashboardResponseSchema = z.object({
  generatedAt: z.string().datetime({ offset: true }),
  tenantId: z.string().uuid().optional(),
  /** Total SBOMs in scope for this tenant */
  sbomCount: z.number().int().nonnegative(),
  /** Vulnerability count bucketed by severity */
  vulnCountBySeverity: z.object({
    critical: z.number().int().nonnegative().default(0),
    high: z.number().int().nonnegative().default(0),
    medium: z.number().int().nonnegative().default(0),
    low: z.number().int().nonnegative().default(0),
    info: z.number().int().nonnegative().default(0),
    unknown: z.number().int().nonnegative().default(0),
  }),
  /** Total vulnerability count (sum of buckets) */
  totalVulnCount: z.number().int().nonnegative(),
  /** Top 5 riskiest components, sorted by `score` desc */
  topRiskyComponents: z.array(TopRiskyComponentSchema).max(5),
  /** Most recent activity (capped at 20) */
  recentActivity: z.array(RecentActivityEntrySchema).max(20),
  /** Aggregate security score 0-100 (100 = perfectly secure) */
  securityScore: z.number().int().min(0).max(100),
  /** Security score trend (last 7 days, oldest first) */
  securityScoreTrend: z.array(z.object({
    date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    score: z.number().int().min(0).max(100),
  })).max(7).default([]),
  /** Model version that produced the security score */
  modelVersion: z.string().default('security-score-v1'),
});
export type SecurityDashboardResponse = z.infer<typeof SecurityDashboardResponseSchema>;

// ---------- JSON-Schema export helper ----------

export function toJSONSchema<T extends z.ZodType>(schema: T): Record<string, unknown> {
  return z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/security/' },
  }) as Record<string, unknown>;
}
