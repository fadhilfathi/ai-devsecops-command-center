/**
 * Cluster model — Kubernetes cluster inventory.
 *
 * Sprint 4: a single AICC tenant may onboard multiple Kubernetes
 * clusters (prod, staging, dev, edge). The cluster is the root
 * inventory node; every namespace, workload, pod, and service is
 * scoped to exactly one cluster.
 *
 * In Sprint 4 the data is sourced from a static snapshot or from
 * the Kubernetes API (read-only). No write operations are
 * performed against the cluster from this model — the model
 * represents the *inferred state*, not the live API state.
 */
import { z } from 'zod';

/** Cluster lifecycle phase. */
export const ClusterPhaseSchema = z.enum([
  'provisioning',
  'active',
  'degraded',
  'draining',
  'archived',
]);
export type ClusterPhase = z.infer<typeof ClusterPhaseSchema>;

export const ClusterProviderSchema = z.enum([
  'eks',
  'gke',
  'aks',
  'oke',
  'openshift',
  'rancher',
  'kind',
  'k3s',
  'self_managed',
  'unknown',
]);
export type ClusterProvider = z.infer<typeof ClusterProviderSchema>;

export const NodeConditionSchema = z.enum([
  'ready',
  'memory_pressure',
  'disk_pressure',
  'pid_pressure',
  'network_unavailable',
  'unschedulable',
]);
export type NodeCondition = z.infer<typeof NodeConditionSchema>;

export const NodeSchema = z.object({
  name: z.string().min(1),
  roles: z.array(z.string()).default([]),
  kubeletVersion: z.string().optional(),
  osImage: z.string().optional(),
  architecture: z.string().optional(),
  cpuCapacityCores: z.number().int().nonnegative().optional(),
  memoryCapacityBytes: z.number().int().nonnegative().optional(),
  podCapacity: z.number().int().nonnegative().optional(),
  conditions: z.array(NodeConditionSchema).default([]),
  unschedulable: z.boolean().default(false),
});
export type Node = z.infer<typeof NodeSchema>;

export const ClusterSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string().min(1).max(200),
  /** Server URL (`https://api.k8s.example.com:6443`). Stored as metadata only. */
  server: z.string().url().optional(),
  provider: ClusterProviderSchema,
  /** Kubernetes minor version (e.g. `1.29`). */
  k8sVersion: z.string().optional(),
  region: z.string().optional(),
  environment: z.enum(['prod', 'staging', 'dev', 'sandbox']).default('dev'),
  phase: ClusterPhaseSchema.default('active'),
  nodeCount: z.number().int().nonnegative().default(0),
  readyNodes: z.number().int().nonnegative().default(0),
  totalCpuCores: z.number().int().nonnegative().default(0),
  totalMemoryBytes: z.number().int().nonnegative().default(0),
  /** Subset of nodes — full detail in the inventory service. */
  nodes: z.array(NodeSchema).default([]),
  /** Integration that owns this cluster. */
  integrationId: z.string().uuid().optional(),
  /** Free-form labels propagated from the cluster. */
  labels: z.record(z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Cluster = z.infer<typeof ClusterSchema>;

export const ClusterListResponseSchema = z.object({
  items: z.array(ClusterSchema),
  total: z.number().int().nonnegative(),
});
export type ClusterListResponse = z.infer<typeof ClusterListResponseSchema>;

export const ClusterConnectionTestRequestSchema = z.object({
  server: z.string().url(),
  /** Bearer token or service account token. Never logged. */
  token: z.string().min(1).optional(),
  /** Base64-encoded CA bundle. */
  caBundle: z.string().optional(),
  /** Skip TLS verification. Off by default. */
  insecureSkipVerify: z.boolean().default(false),
  /** Friendly label for the connection test. */
  name: z.string().min(1).max(200).default('ad-hoc-test'),
});
export type ClusterConnectionTestRequest = z.infer<typeof ClusterConnectionTestRequestSchema>;

export const ClusterConnectionTestResponseSchema = z.object({
  ok: z.boolean(),
  /** Round-trip latency in milliseconds. */
  latencyMs: z.number().int().nonnegative().optional(),
  /** Server-reported Kubernetes version (e.g. `v1.29.4`). */
  serverVersion: z.string().optional(),
  /** Platform / provider, when advertised. */
  platform: z.string().optional(),
  /** Human-readable detail when `ok === false`. Never includes the token. */
  message: z.string().optional(),
  testedAt: z.string().datetime({ offset: true }),
});
export type ClusterConnectionTestResponse = z.infer<typeof ClusterConnectionTestResponseSchema>;

export function toClusterJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(ClusterSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/cluster' },
  }) as Record<string, unknown>;
}
