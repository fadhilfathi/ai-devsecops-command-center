/**
 * Workload model — Kubernetes workload inventory.
 *
 * A *workload* is the abstract concept: a deployable unit that the
 * cluster keeps "the desired state" of. In Kubernetes that maps to
 * Deployments, StatefulSets, DaemonSets, ReplicaSets, and CronJobs.
 * The AICC model unifies them behind a single shape so the dashboard
 * can show a single workload list regardless of the underlying kind.
 */
import { z } from 'zod';

export const WorkloadKindSchema = z.enum([
  'deployment',
  'statefulset',
  'daemonset',
  'replicaset',
  'cronjob',
  'job',
  'pod',
]);
export type WorkloadKind = z.infer<typeof WorkloadKindSchema>;

export const WorkloadHealthSchema = z.enum([
  'healthy',
  'degraded',
  'unhealthy',
  'unknown',
]);
export type WorkloadHealth = z.infer<typeof WorkloadHealthSchema>;

export const WorkloadSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  clusterName: z.string().min(1),
  namespaceId: z.string().uuid().optional(),
  namespace: z.string().min(1),
  /** Kind discriminator. */
  kind: WorkloadKindSchema,
  /** Workload name (Deployment / StatefulSet / DaemonSet / ...). */
  name: z.string().min(1).max(253),
  uid: z.string().optional(),
  /** Image used by the primary container (or the first container when many). */
  image: z.string().optional(),
  /** Image digest (sha256:...) when present. */
  imageDigest: z.string().optional(),
  replicas: z.object({
    desired: z.number().int().nonnegative(),
    ready: z.number().int().nonnegative(),
    updated: z.number().int().nonnegative(),
    available: z.number().int().nonnegative(),
  }).default({ desired: 0, ready: 0, updated: 0, available: 0 }),
  health: WorkloadHealthSchema.default('unknown'),
  /** Conditions surfaced from the workload's `status.conditions` array. */
  conditions: z.array(z.object({
    type: z.string(),
    status: z.enum(['true', 'false', 'unknown']),
    message: z.string().optional(),
    lastTransitionTime: z.string().datetime({ offset: true }).optional(),
  })).default([]),
  labels: z.record(z.string()).default({}),
  /** Container resource requests & limits (merged across containers). */
  resources: z.object({
    cpuRequestsMillicores: z.number().int().nonnegative().default(0),
    cpuLimitsMillicores: z.number().int().nonnegative().default(0),
    memoryRequestsBytes: z.number().int().nonnegative().default(0),
    memoryLimitsBytes: z.number().int().nonnegative().default(0),
  }).default({
    cpuRequestsMillicores: 0,
    cpuLimitsMillicores: 0,
    memoryRequestsBytes: 0,
    memoryLimitsBytes: 0,
  }),
  /** Latest image / config revision. */
  revision: z.string().optional(),
  /** Wall-clock uptime of the current generation. */
  uptimeSeconds: z.number().int().nonnegative().optional(),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Workload = z.infer<typeof WorkloadSchema>;

export const WorkloadListResponseSchema = z.object({
  items: z.array(WorkloadSchema),
  total: z.number().int().nonnegative(),
});
export type WorkloadListResponse = z.infer<typeof WorkloadListResponseSchema>;

export function toWorkloadJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(WorkloadSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/workload' },
  }) as Record<string, unknown>;
}
