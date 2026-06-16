/**
 * Ingress model — Kubernetes Ingress inventory.
 *
 * Ingress is the *layer-7 routing* object in Kubernetes. The AICC
 * model captures:
 *   - the ingress class (nginx, traefik, istio, alb, ...)
 *   - the routing rules (host + path + backend service)
 *   - the TLS configuration (hosts, secret name)
 *   - the optional default backend
 */
import { z } from 'zod';

export const IngressClassSchema = z.enum([
  'nginx',
  'nginx_internal',
  'traefik',
  'istio',
  'alb',
  'gce',
  'kong',
  'unknown',
]);
export type IngressClass = z.infer<typeof IngressClassSchema>;

export const IngressPathTypeSchema = z.enum([
  'Exact',
  'Prefix',
  'ImplementationSpecific',
]);
export type IngressPathType = z.infer<typeof IngressPathTypeSchema>;

export const IngressTlsSchema = z.object({
  hosts: z.array(z.string().min(1)).default([]),
  secretName: z.string().min(1).optional(),
});
export type IngressTls = z.infer<typeof IngressTlsSchema>;

export const IngressRuleSchema = z.object({
  host: z.string().optional(),
  path: z.string().min(1),
  pathType: IngressPathTypeSchema.default('Prefix'),
  serviceName: z.string().min(1),
  servicePort: z.union([z.number().int(), z.string()]),
});
export type IngressRule = z.infer<typeof IngressRuleSchema>;

export const IngressBackendSchema = z.object({
  serviceName: z.string().min(1),
  servicePort: z.union([z.number().int(), z.string()]),
});
export type IngressBackend = z.infer<typeof IngressBackendSchema>;

export const IngressSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  clusterName: z.string().min(1),
  namespace: z.string().min(1),
  name: z.string().min(1).max(253),
  uid: z.string().optional(),
  className: IngressClassSchema.default('nginx'),
  rules: z.array(IngressRuleSchema).default([]),
  tls: z.array(IngressTlsSchema).default([]),
  defaultBackend: IngressBackendSchema.optional(),
  labels: z.record(z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  lastSyncedAt: z.string().datetime({ offset: true }).optional(),
});
export type Ingress = z.infer<typeof IngressSchema>;

export const IngressListResponseSchema = z.object({
  items: z.array(IngressSchema),
  total: z.number().int().nonnegative(),
});
export type IngressListResponse = z.infer<typeof IngressListResponseSchema>;

export function toIngressJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(IngressSchema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/infrastructure/ingress' },
  }) as Record<string, unknown>;
}
