/**
 * DaemonSet model — Kubernetes DaemonSet inventory.
 *
 * DaemonSets run a pod on every node (or a subset of nodes
 * selected by nodeSelector). The AICC model captures the
 * DaemonSet-specific scheduling status (how many pods are
 * scheduled, ready, up-to-date, available, misscheduled) on
 * top of the workload shape.
 */
import { z } from 'zod';
import { WorkloadSchema } from './workload.model.js';

export const DaemonSetUpdateStrategySchema = z.enum([
  'rolling_update',
  'on_delete',
  'in_place',
]);
export type DaemonSetUpdateStrategy = z.infer<typeof DaemonSetUpdateStrategySchema>;

export const DaemonSetSchema = WorkloadSchema.extend({
  kind: z.literal('daemonset'),
  updateStrategy: DaemonSetUpdateStrategySchema.default('rolling_update'),
  /** Total pods that should be scheduled. Matches `nodeCount` of the cluster. */
  desiredNumberScheduled: z.number().int().nonnegative().default(0),
  /** Total pods currently scheduled. */
  currentNumberScheduled: z.number().int().nonnegative().default(0),
  /** Pods that are ready (passed readiness probe). */
  numberReady: z.number().int().nonnegative().default(0),
  /** Pods that are running on a node that should not have one. */
  numberMisscheduled: z.number().int().nonnegative().default(0),
});
export type DaemonSet = z.infer<typeof DaemonSetSchema>;

export const DaemonSetListResponseSchema = z.object({
  items: z.array(DaemonSetSchema),
  total: z.number().int().nonnegative(),
});
export type DaemonSetListResponse = z.infer<typeof DaemonSetListResponseSchema>;

export function toDaemonSetJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(DaemonSetSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/daemonset' },
  }) as Record<string, unknown>;
}
