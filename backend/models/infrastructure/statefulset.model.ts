/**
 * StatefulSet model — Kubernetes StatefulSet inventory.
 *
 * StatefulSets differ from Deployments in that pods have stable
 * network identities (ordinal index) and persistent storage
 * (volumeClaimTemplates). The AICC model extends the workload
 * shape with the StatefulSet-specific fields.
 */
import { z } from 'zod';
import { WorkloadSchema } from './workload.model.js';

export const StatefulSetUpdateStrategySchema = z.enum([
  'rolling_update',
  'on_delete',
  'in_place',
]);
export type StatefulSetUpdateStrategy = z.infer<typeof StatefulSetUpdateStrategySchema>;

export const PodManagementPolicySchema = z.enum([
  'ordered_ready',
  'parallel',
]);
export type PodManagementPolicy = z.infer<typeof PodManagementPolicySchema>;

export const VolumeClaimTemplateSchema = z.object({
  name: z.string().min(1),
  storageClassName: z.string().optional(),
  sizeBytes: z.number().int().nonnegative(),
  accessModes: z.array(z.enum(['ReadWriteOnce', 'ReadOnlyMany', 'ReadWriteMany'])).default(['ReadWriteOnce']),
});
export type VolumeClaimTemplate = z.infer<typeof VolumeClaimTemplateSchema>;

export const StatefulSetSchema = WorkloadSchema.extend({
  kind: z.literal('statefulset'),
  serviceName: z.string().min(1),
  podManagementPolicy: PodManagementPolicySchema.default('ordered_ready'),
  updateStrategy: StatefulSetUpdateStrategySchema.default('rolling_update'),
  volumeClaimTemplates: z.array(VolumeClaimTemplateSchema).default([]),
  currentRevision: z.string().optional(),
  updateRevision: z.string().optional(),
});
export type StatefulSet = z.infer<typeof StatefulSetSchema>;

export const StatefulSetListResponseSchema = z.object({
  items: z.array(StatefulSetSchema),
  total: z.number().int().nonnegative(),
});
export type StatefulSetListResponse = z.infer<typeof StatefulSetListResponseSchema>;

export function toStatefulSetJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(StatefulSetSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/statefulset' },
  }) as Record<string, unknown>;
}
