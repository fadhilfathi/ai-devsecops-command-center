/**
 * Pod model — Kubernetes pod inventory.
 *
 * The pod is the smallest deployable unit in Kubernetes and the
 * natural observation point for both health and runtime security.
 * The AICC model keeps the pod's spec summary (namespace, owner,
 * node, containers), the status (phase, ready, restarts), the
 * *last termination reason* (CrashLoopBackOff, OOMKilled,
 * ImagePullBackOff, ...), and the runtime-security posture
 * (privileged, hostPath, rootUser, dangerous capabilities).
 */
import { z } from 'zod';

export const PodPhaseSchema = z.enum([
  'pending',
  'running',
  'succeeded',
  'failed',
  'unknown',
]);
export type PodPhase = z.infer<typeof PodPhaseSchema>;

export const PodConditionSchema = z.enum([
  'pod_scheduled',
  'ready',
  'initialized',
  'containers_ready',
  'unschedulable',
]);
export type PodCondition = z.infer<typeof PodConditionSchema>;

/** Common pod-level termination reasons we surface in the UI. */
export const PodTerminationReasonSchema = z.enum([
  'crash_loop_back_off',
  'image_pull_back_off',
  'err_image_pull',
  'err_image_never_pull',
  'create_container_config_error',
  'invalid_image_name',
  'oom_killed',
  'evicted',
  'node_lost',
  'node_pressure',
  'completed',
  'error',
  'container_status_unknown',
  'unknown',
]);
export type PodTerminationReason = z.infer<typeof PodTerminationReasonSchema>;

export const ContainerStateSchema = z.enum([
  'waiting',
  'running',
  'terminated',
]);
export type ContainerState = z.infer<typeof ContainerStateSchema>;

export const ContainerSchema = z.object({
  name: z.string().min(1),
  image: z.string().min(1),
  imageDigest: z.string().optional(),
  state: ContainerStateSchema.default('waiting'),
  ready: z.boolean().default(false),
  restartCount: z.number().int().nonnegative().default(0),
  /** Last termination reason (from `state.terminated.reason`). */
  lastTerminationReason: PodTerminationReasonSchema.default('unknown'),
  /** Free-form message associated with the last termination. */
  lastTerminationMessage: z.string().optional(),
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
  /** Whether the container runs as privileged. */
  privileged: z.boolean().default(false),
  /** Whether the container runs as root (uid 0). */
  runAsRoot: z.boolean().default(false),
  /** Linux capabilities added beyond the default. */
  addedCapabilities: z.array(z.string()).default([]),
  /** hostPath volumes mounted by this container. */
  hostPaths: z.array(z.string()).default([]),
});
export type Container = z.infer<typeof ContainerSchema>;

export const PodSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  clusterName: z.string().min(1),
  namespace: z.string().min(1),
  name: z.string().min(1).max(253),
  uid: z.string().optional(),
  phase: PodPhaseSchema.default('pending'),
  node: z.string().optional(),
  podIp: z.string().optional(),
  /** Owning workload (Deployment / StatefulSet / DaemonSet / ...). */
  ownerKind: z.string().optional(),
  ownerName: z.string().optional(),
  /** Service account the pod is running as. */
  serviceAccount: z.string().optional(),
  /** Container specs. */
  containers: z.array(ContainerSchema).min(1),
  conditions: z.array(z.object({
    type: PodConditionSchema,
    status: z.enum(['true', 'false', 'unknown']),
    message: z.string().optional(),
    lastTransitionTime: z.string().datetime({ offset: true }).optional(),
  })).default([]),
  restarts: z.number().int().nonnegative().default(0),
  startedAt: z.string().datetime({ offset: true }).optional(),
  /** Aggregate of `lastTerminationReason` across containers. */
  lastTerminationReason: PodTerminationReasonSchema.default('unknown'),
  labels: z.record(z.string()).default({}),
  annotations: z.record(z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Pod = z.infer<typeof PodSchema>;

export const PodListResponseSchema = z.object({
  items: z.array(PodSchema),
  total: z.number().int().nonnegative(),
});
export type PodListResponse = z.infer<typeof PodListResponseSchema>;

export function toPodJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(PodSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/pod' },
  }) as Record<string, unknown>;
}
