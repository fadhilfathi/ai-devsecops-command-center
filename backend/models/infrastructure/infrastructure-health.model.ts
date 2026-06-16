/**
 * Infrastructure health model — health scores for clusters,
 * namespaces, workloads, and pods.
 *
 * The health engine combines signals from the workload / pod
 * inventories (CrashLoopBackOff, OOMKilled, Pending, restart
 * storms, node pressure) and the runtime risk engine into a single
 * 0..100 score per object. The score is bucketed into a band
 * (A..F) and a discrete status (`healthy` / `degraded` /
 * `unhealthy` / `unknown`).
 */
import { z } from 'zod';

export const HealthStatusSchema = z.enum([
  'healthy',
  'degraded',
  'unhealthy',
  'unknown',
]);
export type HealthStatus = z.infer<typeof HealthStatusSchema>;

export const HealthBandSchema = z.enum(['A', 'B', 'C', 'D', 'F']);
export type HealthBand = z.infer<typeof HealthBandSchema>;

export const HealthIssueSeveritySchema = z.enum([
  'critical',
  'high',
  'medium',
  'low',
  'info',
]);
export type HealthIssueSeverity = z.infer<typeof HealthIssueSeveritySchema>;

export const HealthIssueKindSchema = z.enum([
  'crash_loop_back_off',
  'image_pull_back_off',
  'oom_killed',
  'pending_pod',
  'failed_pod',
  'restart_storm',
  'node_pressure',
  'unschedulable_workload',
  'runtime_risk',
  'cost_anomaly',
  'unknown',
]);
export type HealthIssueKind = z.infer<typeof HealthIssueKindSchema>;

export const HealthIssueSchema = z.object({
  id: z.string().uuid(),
  kind: HealthIssueKindSchema,
  severity: HealthIssueSeveritySchema,
  message: z.string().min(1),
  /** Affected object ref. */
  subject: z.object({
    kind: z.string().min(1),
    name: z.string().min(1),
    namespace: z.string().optional(),
    clusterId: z.string().uuid().optional(),
  }),
  detectedAt: z.string().datetime({ offset: true }),
  /** Optional remediation hint. */
  remediation: z.string().optional(),
});
export type HealthIssue = z.infer<typeof HealthIssueSchema>;

export const HealthRecommendationSchema = z.object({
  id: z.string().uuid(),
  priority: z.enum(['p0', 'p1', 'p2', 'p3']),
  title: z.string().min(1),
  detail: z.string().min(1),
  /** Actionable: e.g. `kubectl rollout restart deploy/payments-api`. */
  action: z.string().optional(),
  /** Rule(s) that produced this recommendation. */
  ruleIds: z.array(z.string()).default([]),
  /** Number of issues this would address. */
  affectedCount: z.number().int().nonnegative().default(0),
});
export type HealthRecommendation = z.infer<typeof HealthRecommendationSchema>;

export const HealthScoreSchema = z.object({
  /** 0..100; higher is healthier. */
  score: z.number().int().min(0).max(100),
  band: HealthBandSchema,
  status: HealthStatusSchema,
  /** Counts that produced the score. */
  counts: z.object({
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    info: z.number().int().nonnegative(),
  }),
  generatedAt: z.string().datetime({ offset: true }),
});
export type HealthScore = z.infer<typeof HealthScoreSchema>;

export const HealthScopeSchema = z.enum(['cluster', 'namespace', 'workload', 'pod']);
export type HealthScope = z.infer<typeof HealthScopeSchema>;

export const InfrastructureHealthSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  scope: HealthScopeSchema,
  /** Ref to the scoped object. */
  subject: z.object({
    kind: z.string().min(1),
    name: z.string().min(1),
    namespace: z.string().optional(),
    clusterId: z.string().uuid().optional(),
  }),
  score: HealthScoreSchema,
  issues: z.array(HealthIssueSchema).default([]),
  recommendations: z.array(HealthRecommendationSchema).default([]),
  generatedAt: z.string().datetime({ offset: true }),
});
export type InfrastructureHealth = z.infer<typeof InfrastructureHealthSchema>;

export const InfrastructureHealthListResponseSchema = z.object({
  items: z.array(InfrastructureHealthSchema),
  total: z.number().int().nonnegative(),
});
export type InfrastructureHealthListResponse = z.infer<typeof InfrastructureHealthListResponseSchema>;

export function toInfrastructureHealthJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(InfrastructureHealthSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/health' },
  }) as Record<string, unknown>;
}
