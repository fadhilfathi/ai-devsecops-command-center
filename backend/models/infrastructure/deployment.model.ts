/**
 * Deployment model — Kubernetes Deployment inventory.
 *
 * A Deployment is the *workload* abstraction that owns a ReplicaSet
 * and a pod template. The AICC deployment model extends the
 * workload model with a deployment-specific summary: the rolling
 * update strategy, the current/previous ReplicaSet, and the last
 * applied revision annotation. This is the view most often wanted
 * by developers ("did my last deploy land?") and by SREs ("is the
 * rollout healthy?").
 */
import { z } from 'zod';
import { WorkloadSchema } from './workload.model.js';

export const DeploymentStrategyTypeSchema = z.enum([
  'rolling_update',
  'recreate',
  'in_place',
]);
export type DeploymentStrategyType = z.infer<typeof DeploymentStrategyTypeSchema>;

export const DeploymentRolloutStatusSchema = z.enum([
  'complete',
  'progressing',
  'paused',
  'failed',
  'unknown',
]);
export type DeploymentRolloutStatus = z.infer<typeof DeploymentRolloutStatusSchema>;

export const DeploymentSchema = WorkloadSchema.extend({
  kind: z.literal('deployment'),
  strategy: DeploymentStrategyTypeSchema.default('rolling_update'),
  rollingUpdate: z.object({
    maxSurge: z.union([z.number().int().nonnegative(), z.string()]).optional(),
    maxUnavailable: z.union([z.number().int().nonnegative(), z.string()]).optional(),
  }).partial().default({}),
  /** ReplicaSet name currently serving traffic. */
  currentReplicaSet: z.string().optional(),
  /** ReplicaSet name from the previous generation. Kept for rollback. */
  previousReplicaSet: z.string().optional(),
  /** Number of pods from the old ReplicaSet that are still terminating. */
  terminatingReplicas: z.number().int().nonnegative().default(0),
  /** Status surfaced by `deployment.status.conditions[DeploymentProgressing]`. */
  rollout: DeploymentRolloutStatusSchema.default('unknown'),
  /** Last known change cause (`kubectl.kubernetes.io/change-cause`). */
  changeCause: z.string().optional(),
  /** Revision history limit, captured from the spec. */
  revisionHistoryLimit: z.number().int().nonnegative().optional(),
  paused: z.boolean().default(false),
});
export type Deployment = z.infer<typeof DeploymentSchema>;

export const DeploymentListResponseSchema = z.object({
  items: z.array(DeploymentSchema),
  total: z.number().int().nonnegative(),
});
export type DeploymentListResponse = z.infer<typeof DeploymentListResponseSchema>;

export function toDeploymentJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(DeploymentSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/deployment' },
  }) as Record<string, unknown>;
}
