/**
 * NetworkPolicy model — Kubernetes NetworkPolicy inventory.
 *
 * A NetworkPolicy scopes ingress/egress traffic to a set of pods
 * (via `podSelector`). AICC uses it to annotate the topology graph
 * with the effective reachability between workloads: `unrestricted`
 * (no policy selects the target), `allowed` (a rule permits the
 * source), or `denied` (policies select the target but none permit
 * the source).
 *
 * Only `matchLabels`-style selectors are modelled — `matchExpressions`
 * is out of scope for Sprint 5 (see ADR 0011).
 */
import { z } from 'zod';

export const NetworkPolicyTypeSchema = z.enum(['Ingress', 'Egress']);
export type NetworkPolicyType = z.infer<typeof NetworkPolicyTypeSchema>;

/** matchLabels-only selector; empty object selects all pods in scope. */
export const LabelSelectorSchema = z.record(z.string(), z.string()).default({});
export type LabelSelector = z.infer<typeof LabelSelectorSchema>;

export const IpBlockSchema = z.object({
  cidr: z.string().min(1),
  except: z.array(z.string()).default([]),
});
export type IpBlock = z.infer<typeof IpBlockSchema>;

export const NetworkPolicyPeerSchema = z.object({
  podSelector: LabelSelectorSchema.optional(),
  namespaceSelector: LabelSelectorSchema.optional(),
  ipBlock: IpBlockSchema.optional(),
});
export type NetworkPolicyPeer = z.infer<typeof NetworkPolicyPeerSchema>;

export const NetworkPolicyPortSchema = z.object({
  protocol: z.enum(['TCP', 'UDP', 'SCTP']).optional(),
  port: z.union([z.number().int(), z.string()]).optional(),
});
export type NetworkPolicyPort = z.infer<typeof NetworkPolicyPortSchema>;

export const NetworkPolicyIngressRuleSchema = z.object({
  from: z.array(NetworkPolicyPeerSchema).default([]),
  ports: z.array(NetworkPolicyPortSchema).default([]),
});
export type NetworkPolicyIngressRule = z.infer<typeof NetworkPolicyIngressRuleSchema>;

export const NetworkPolicyEgressRuleSchema = z.object({
  to: z.array(NetworkPolicyPeerSchema).default([]),
  ports: z.array(NetworkPolicyPortSchema).default([]),
});
export type NetworkPolicyEgressRule = z.infer<typeof NetworkPolicyEgressRuleSchema>;

export const NetworkPolicySchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  clusterId: z.string().uuid(),
  namespace: z.string().min(1),
  name: z.string().min(1).max(253),
  /** Pods this policy applies to; empty selector = all pods in the namespace. */
  podSelector: LabelSelectorSchema,
  policyTypes: z.array(NetworkPolicyTypeSchema).default(['Ingress']),
  ingress: z.array(NetworkPolicyIngressRuleSchema).default([]),
  egress: z.array(NetworkPolicyEgressRuleSchema).default([]),
  labels: z.record(z.string(), z.string()).default({}),
  createdAt: z.string().datetime({ offset: true }),
});
export type NetworkPolicy = z.infer<typeof NetworkPolicySchema>;

export const NetworkPolicyListResponseSchema = z.object({
  items: z.array(NetworkPolicySchema),
  total: z.number().int().nonnegative(),
});
export type NetworkPolicyListResponse = z.infer<typeof NetworkPolicyListResponseSchema>;

export function toNetworkPolicyJSONSchema(): Record<string, unknown> {
  return z.toJSONSchema(NetworkPolicySchema, {
    target: 'draft-2020-12',
  }) as Record<string, unknown>;
}
