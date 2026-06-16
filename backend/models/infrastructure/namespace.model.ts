/**
 * Namespace model — Kubernetes namespace inventory.
 *
 * Namespaces are the *security boundary* inside a cluster for
 * almost every operator. They are also the unit of RBAC scoping,
 * network policy, and resource quota. The AICC namespace model
 * captures both the metadata and the operational signals (workload
 * count, pod count, running pods, failing pods, pending pods,
 * restart storms) so that the dashboard can render a per-namespace
 * health card without an extra round trip.
 */
import { z } from 'zod';

export const NamespacePhaseSchema = z.enum(['active', 'terminating']);
export type NamespacePhase = z.infer<typeof NamespacePhaseSchema>;

export const NamespaceSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  /** Owning cluster id. */
  clusterId: z.string().uuid(),
  /** Cluster name — denormalised for list views. */
  clusterName: z.string().min(1),
  /** Namespace name. */
  name: z.string().min(1).max(253).regex(/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/),
  uid: z.string().optional(),
  phase: NamespacePhaseSchema.default('active'),
  /** Aggregate workload counts (deployments + statefulsets + daemonsets + cronjobs). */
  workloadCount: z.number().int().nonnegative().default(0),
  podCount: z.number().int().nonnegative().default(0),
  runningPods: z.number().int().nonnegative().default(0),
  pendingPods: z.number().int().nonnegative().default(0),
  failedPods: z.number().int().nonnegative().default(0),
  serviceCount: z.number().int().nonnegative().default(0),
  /** Last 1h restart count across all pods in the namespace. */
  restartsLast1h: z.number().int().nonnegative().default(0),
  /** Labels propagated from the namespace. */
  labels: z.record(z.string()).default({}),
  /** Annotations propagated from the namespace. */
  annotations: z.record(z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Namespace = z.infer<typeof NamespaceSchema>;

export const NamespaceListResponseSchema = z.object({
  items: z.array(NamespaceSchema),
  total: z.number().int().nonnegative(),
});
export type NamespaceListResponse = z.infer<typeof NamespaceListResponseSchema>;

export function toNamespaceJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(NamespaceSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/namespace' },
  }) as Record<string, unknown>;
}
