/**
 * Topology model — the unified application / service / dependency
 * graph for Kubernetes-resident workloads.
 *
 * The model captures the three layers AICC needs to render the
 * topology viewer:
 *   - **Nodes**: clusters, namespaces, services, workloads, pods
 *   - **Edges**: depends_on, routes_to, exposes, owns, calls
 *   - **Sub-graphs**: application slices grouped by ingress,
 *     namespace, or a user-defined label selector
 *
 * The same shape is used for the Service Map (services only) and
 * the Application Graph (services + workloads + ingresses).
 */
import { z } from 'zod';

export const TopologyNodeKindSchema = z.enum([
  'cluster',
  'namespace',
  'service',
  'workload',
  'pod',
  'ingress',
  'external',
]);
export type TopologyNodeKind = z.infer<typeof TopologyNodeKindSchema>;

export const TopologyEdgeKindSchema = z.enum([
  'depends_on',
  'routes_to',
  'exposes',
  'owns',
  'calls',
  'selects',
  'in_namespace',
  'unknown',
]);
export type TopologyEdgeKind = z.infer<typeof TopologyEdgeKindSchema>;

export const TopologyNodeSchema = z.object({
  id: z.string().uuid(),
  /** Display label (e.g. `payments-api`). */
  label: z.string().min(1),
  kind: TopologyNodeKindSchema,
  /** Free-form namespace the node belongs to, when applicable. */
  namespace: z.string().optional(),
  /** Cluster id, when the node is cluster-scoped. */
  clusterId: z.string().uuid().optional(),
  /** Cluster name, denormalised. */
  clusterName: z.string().optional(),
  /** Risk score for the node (0..100; higher is riskier). */
  riskScore: z.number().min(0).max(100).default(0),
  /** Tags propagated from labels / metadata. */
  tags: z.array(z.string()).default([]),
  /** Optional positional hints from the layout engine. */
  position: z.object({ x: z.number(), y: z.number() }).optional(),
  metadata: z.record(z.unknown()).default({}),
});
export type TopologyNode = z.infer<typeof TopologyNodeSchema>;

export const TopologyEdgeSchema = z.object({
  id: z.string().uuid(),
  source: z.string().uuid(),
  target: z.string().uuid(),
  kind: TopologyEdgeKindSchema,
  /** Optional weight used for the layout (1.0 = default). */
  weight: z.number().min(0).max(10).default(1.0),
  /** Edge label (e.g. `GET /users`). */
  label: z.string().optional(),
  metadata: z.record(z.unknown()).default({}),
});
export type TopologyEdge = z.infer<typeof TopologyEdgeSchema>;

export const TopologyGraphSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  /** Display name (e.g. `payments-platform`). */
  name: z.string().min(1).max(200),
  /** Cluster scope (omitted = tenant-wide). */
  clusterId: z.string().uuid().optional(),
  /** Optional namespace filter applied when building the graph. */
  namespace: z.string().optional(),
  /** Free-form group label (e.g. `production`, `staging`). */
  group: z.string().optional(),
  nodes: z.array(TopologyNodeSchema),
  edges: z.array(TopologyEdgeSchema),
  generatedAt: z.string().datetime({ offset: true }),
});
export type TopologyGraph = z.infer<typeof TopologyGraphSchema>;

export const TopologyListResponseSchema = z.object({
  items: z.array(TopologyGraphSchema),
  total: z.number().int().nonnegative(),
});
export type TopologyListResponse = z.infer<typeof TopologyListResponseSchema>;

export function toTopologyJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(TopologyGraphSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/topology' },
  }) as Record<string, unknown>;
}
