/**
 * Cost analysis model — Kubernetes cost intelligence.
 *
 * The cost engine takes workload / pod resource requests & limits
 * and produces:
 *   - per-workload **cost estimates** (hourly, monthly)
 *   - **waste reports** (over-provisioned requests vs. actual use)
 *   - **under-utilization** findings (limits far above request)
 *   - **optimization recommendations** with projected savings
 *
 * The model is intentionally provider-agnostic: the pricing
 * defaults are reasonable ballpark USD/hour figures for on-demand
 * x86_64 compute. The inventory / integration layer can override
 * the rates per cluster / node-pool in a future sprint.
 */
import { z } from 'zod';

export const ResourceDimensionSchema = z.enum(['cpu', 'memory']);
export type ResourceDimension = z.infer<typeof ResourceDimensionSchema>;

export const OptimizationActionSchema = z.enum([
  'right_size_requests',
  'right_size_limits',
  'add_limits',
  'add_requests',
  'remove_unused_workload',
  'consolidate_replicas',
  'use_spot_or_preemptible',
  'unknown',
]);
export type OptimizationAction = z.infer<typeof OptimizationActionSchema>;

/** Per-cluster pricing rates (USD/hour per unit). */
export const PricingRatesSchema = z.object({
  /** USD per vCPU hour. */
  cpuUsdPerHour: z.number().nonnegative().default(0.0316),
  /** USD per GiB hour. */
  memoryUsdPerHour: z.number().nonnegative().default(0.0042),
  /** USD per GPU hour. */
  gpuUsdPerHour: z.number().nonnegative().default(2.5),
  /** USD per GB egress network hour (rough average). */
  networkEgressUsdPerHour: z.number().nonnegative().default(0.0),
  currency: z.string().length(3).default('USD'),
});
export type PricingRates = z.infer<typeof PricingRatesSchema>;

export const WorkloadCostSchema = z.object({
  workloadId: z.string().uuid(),
  workloadName: z.string().min(1),
  namespace: z.string().min(1),
  kind: z.string().min(1),
  /** Current monthly cost (USD) based on requests. */
  currentMonthlyUsd: z.number().nonnegative(),
  /** Recommended monthly cost (USD) after applying recommendations. */
  recommendedMonthlyUsd: z.number().nonnegative(),
  /** Potential monthly savings (USD) — `current - recommended`. */
  potentialMonthlySavingsUsd: z.number().nonnegative(),
  /** Resource utilisation estimates (0..1). */
  utilisation: z.object({
    cpuP50: z.number().min(0).max(1).default(0),
    cpuP95: z.number().min(0).max(1).default(0),
    memoryP50: z.number().min(0).max(1).default(0),
    memoryP95: z.number().min(0).max(1).default(0),
  }).default({ cpuP50: 0, cpuP95: 0, memoryP50: 0, memoryP95: 0 }),
  /** Per-dimension requests vs. actual use. */
  requests: z.object({
    cpuMillicores: z.number().int().nonnegative(),
    memoryBytes: z.number().int().nonnegative(),
  }),
  /** Per-dimension limits. */
  limits: z.object({
    cpuMillicores: z.number().int().nonnegative(),
    memoryBytes: z.number().int().nonnegative(),
  }),
});
export type WorkloadCost = z.infer<typeof WorkloadCostSchema>;

export const CostFindingSchema = z.object({
  id: z.string().uuid(),
  kind: z.enum([
    'over_provisioned_cpu',
    'over_provisioned_memory',
    'under_utilized_cpu',
    'under_utilized_memory',
    'missing_requests',
    'missing_limits',
    'noisy_neighbour',
    'cold_workload',
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info', 'unknown']),
  message: z.string().min(1),
  dimension: ResourceDimensionSchema.optional(),
  /** Affected workload id. */
  workloadId: z.string().uuid().optional(),
  workloadName: z.string().optional(),
  namespace: z.string().optional(),
  /** Estimated monthly savings if the issue is addressed. */
  monthlySavingsUsd: z.number().nonnegative().default(0),
  /** Free-form data (utilisation snapshots, ratios, etc.). */
  data: z.record(z.unknown()).default({}),
  detectedAt: z.string().datetime({ offset: true }),
});
export type CostFinding = z.infer<typeof CostFindingSchema>;

export const CostRecommendationSchema = z.object({
  id: z.string().uuid(),
  action: OptimizationActionSchema,
  priority: z.enum(['p0', 'p1', 'p2', 'p3']),
  title: z.string().min(1),
  detail: z.string().min(1),
  /** Affected workload id(s). */
  workloadIds: z.array(z.string().uuid()).default([]),
  /** Projected monthly savings (USD). */
  monthlySavingsUsd: z.number().nonnegative(),
  /** Annualised savings (USD). */
  annualSavingsUsd: z.number().nonnegative(),
  /** Action payload — a hint for the operator. */
  actionPayload: z.record(z.unknown()).default({}),
  createdAt: z.string().datetime({ offset: true }),
});
export type CostRecommendation = z.infer<typeof CostRecommendationSchema>;

export const CostAnalysisSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid().optional(),
  /** Inclusive analysis window. */
  windowStart: z.string().datetime({ offset: true }),
  windowEnd: z.string().datetime({ offset: true }),
  pricing: PricingRatesSchema,
  /** Total current monthly cost across the scope (USD). */
  currentMonthlyUsd: z.number().nonnegative(),
  /** Total recommended monthly cost (USD). */
  recommendedMonthlyUsd: z.number().nonnegative(),
  /** Total potential monthly savings (USD). */
  potentialMonthlySavingsUsd: z.number().nonnegative(),
  /** Per-workload breakdown. */
  workloads: z.array(WorkloadCostSchema),
  /** Granular findings. */
  findings: z.array(CostFindingSchema),
  /** Actionable recommendations (sorted by priority). */
  recommendations: z.array(CostRecommendationSchema),
  generatedAt: z.string().datetime({ offset: true }),
});
export type CostAnalysis = z.infer<typeof CostAnalysisSchema>;

export const CostAnalysisListResponseSchema = z.object({
  items: z.array(CostAnalysisSchema),
  total: z.number().int().nonnegative(),
});
export type CostAnalysisListResponse = z.infer<typeof CostAnalysisListResponseSchema>;

export function toCostAnalysisJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(CostAnalysisSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/cost-analysis' },
  }) as Record<string, unknown>;
}
