/**
 * Service model — Kubernetes Service inventory.
 *
 * In Kubernetes a Service is a stable virtual IP and DNS name that
 * fronts a set of pods. It is the *load-balancer abstraction* the
 * AICC topology engine uses to derive application graphs.
 *
 * The AICC Service model captures:
 *   - the spec (type, selector, ports)
 *   - the resolved endpoints (pod IPs behind the selector)
 *   - the optional Ingress / backend wiring (one-to-many)
 */
import { z } from 'zod';

export const ServiceTypeSchema = z.enum([
  'cluster_ip',
  'node_port',
  'load_balancer',
  'external_name',
]);
export type ServiceType = z.infer<typeof ServiceTypeSchema>;

export const ServicePortSchema = z.object({
  name: z.string().optional(),
  protocol: z.enum(['TCP', 'UDP', 'SCTP']).default('TCP'),
  port: z.number().int().min(1).max(65535),
  targetPort: z.union([z.number().int(), z.string()]).optional(),
  nodePort: z.number().int().min(30000).max(32767).optional(),
});
export type ServicePort = z.infer<typeof ServicePortSchema>;

export const ServiceEndpointSchema = z.object({
  podName: z.string().min(1),
  podUid: z.string().optional(),
  podIp: z.string().optional(),
  nodeName: z.string().optional(),
  ready: z.boolean().default(true),
});
export type ServiceEndpoint = z.infer<typeof ServiceEndpointSchema>;

export const ServiceSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  clusterName: z.string().min(1),
  namespace: z.string().min(1),
  name: z.string().min(1).max(253),
  uid: z.string().optional(),
  type: ServiceTypeSchema.default('cluster_ip'),
  clusterIp: z.string().optional(),
  externalIp: z.array(z.string()).default([]),
  selector: z.record(z.string()).default({}),
  ports: z.array(ServicePortSchema).default([]),
  endpoints: z.array(ServiceEndpointSchema).default([]),
  /** Stable, normalised FQDN (`<svc>.<ns>.svc.cluster.local`). */
  fqdn: z.string().optional(),
  /** Session affinity (`None` / `ClientIP` / `ClientIPTimeout`). */
  sessionAffinity: z.enum(['none', 'client_ip']).default('none'),
  /** Whether the service has any ready endpoints. */
  hasReadyEndpoints: z.boolean().default(false),
  /** Ingress ids that route traffic to this service. */
  ingressIds: z.array(z.string().uuid()).default([]),
  labels: z.record(z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Service = z.infer<typeof ServiceSchema>;

export const ServiceListResponseSchema = z.object({
  items: z.array(ServiceSchema),
  total: z.number().int().nonnegative(),
});
export type ServiceListResponse = z.infer<typeof ServiceListResponseSchema>;

export function toServiceJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(ServiceSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/service' },
  }) as Record<string, unknown>;
}
