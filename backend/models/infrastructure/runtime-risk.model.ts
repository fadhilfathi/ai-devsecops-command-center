/**
 * Runtime risk model — Runtime security findings on Kubernetes
 * workloads, pods, and supporting objects.
 *
 * A RuntimeRisk is the per-finding record produced by the runtime
 * security engine. It captures:
 *   - the affected object (kind + namespace + name + cluster)
 *   - the rule that fired (id, name, category)
 *   - the severity (`critical` / `high` / `medium` / `low` /
 *     `info` / `unknown`)
 *   - a short, deterministic remediation hint
 *   - the **risk level** for the runtime security report
 *     (`critical` / `high` / `medium` / `low`)
 *
 * The category taxonomy follows the Kubernetes Hardening Guide
 * (CIS Benchmark §5) categories, with AICC-specific extensions for
 * pod-level risks (image digest pinning, capability drift).
 */
import { z } from 'zod';

export const RiskCategorySchema = z.enum([
  'privileged_container',
  'host_path_volume',
  'host_network',
  'host_pid',
  'host_ipc',
  'root_user',
  'dangerous_capability',
  'unsafe_security_context',
  'service_account_risk',
  'rbac_risk',
  'image_risk',
  'network_policy_missing',
  'resource_limits_missing',
  'secrets_in_env',
  'automount_service_account_token',
  'unknown',
]);
export type RiskCategory = z.infer<typeof RiskCategorySchema>;

export const RiskLevelSchema = z.enum(['critical', 'high', 'medium', 'low']);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const RiskSubjectSchema = z.enum([
  'pod',
  'workload',
  'service',
  'service_account',
  'role_binding',
  'cluster_role_binding',
  'ingress',
  'config_map',
  'secret',
  'unknown',
]);
export type RiskSubject = z.infer<typeof RiskSubjectSchema>;

export const RuntimeRiskSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  clusterName: z.string().min(1),
  namespace: z.string().min(1),
  subject: RiskSubjectSchema,
  subjectKind: z.string().min(1),
  subjectName: z.string().min(1),
  /** Rule id. Stable across runs — used to deduplicate. */
  ruleId: z.string().min(1),
  /** Human-readable rule name. */
  ruleName: z.string().min(1),
  category: RiskCategorySchema,
  level: RiskLevelSchema,
  /** Severity used in incident correlation (`critical` / `high` / `medium` / `low` / `info` / `unknown`). */
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info', 'unknown']),
  message: z.string().min(1),
  /** Field path inside the manifest that triggered the rule. */
  evidencePath: z.string().optional(),
  /** The value at the evidence path. */
  evidenceValue: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
  remediation: z.string().min(1),
  /** References (CIS control ids, OWASP links). */
  references: z.array(z.string().url()).default([]),
  detectedAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
});
export type RuntimeRisk = z.infer<typeof RuntimeRiskSchema>;

export const RuntimeRiskListResponseSchema = z.object({
  items: z.array(RuntimeRiskSchema),
  total: z.number().int().nonnegative(),
});
export type RuntimeRiskListResponse = z.infer<typeof RuntimeRiskListResponseSchema>;

/**
 * Runtime security report — the rollup produced for a cluster /
 * tenant on demand. The `riskLevel` is the highest level of any
 * contained finding; the `score` is a 0..100 value where 100
 * means "no risks detected".
 */
export const RuntimeSecurityReportSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid().optional(),
  /** Inclusive time window. */
  windowStart: z.string().datetime({ offset: true }),
  windowEnd: z.string().datetime({ offset: true }),
  /** Highest single risk level across findings. */
  riskLevel: RiskLevelSchema,
  /** 0..100 — lower means more risk. */
  score: z.number().int().min(0).max(100),
  /** Per-level counters. */
  counts: z.object({
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
  }),
  /** Per-category counters. */
  categoryCounts: z.record(z.number().int().nonnegative()).default({}),
  findings: z.array(RuntimeRiskSchema),
  /** Top remediation recommendations. */
  recommendations: z.array(z.object({
    title: z.string().min(1),
    detail: z.string().min(1),
    level: RiskLevelSchema,
    affectedCount: z.number().int().nonnegative(),
  })).default([]),
  generatedAt: z.string().datetime({ offset: true }),
});
export type RuntimeSecurityReport = z.infer<typeof RuntimeSecurityReportSchema>;

export function toRuntimeRiskJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(RuntimeRiskSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/runtime-risk' },
  }) as Record<string, unknown>;
}
