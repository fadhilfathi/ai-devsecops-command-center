/**
 * Runtime security rules.
 *
 * Each rule is a pure function: given a snapshot of inventory
 * (pods, workloads, services, ServiceAccounts, RoleBindings),
 * produce zero or more `RuntimeRisk` findings.
 *
 * Rules are intentionally fine-grained (one rule per finding
 * class) so the dashboard can list every instance of a finding
 * class (e.g. all privileged containers) and the runtime
 * security report can roll up at any level.
 *
 * Categories follow the CIS Kubernetes Benchmark §5 + the AICC
 * extensions (capability drift, image digest pinning).
 */
import type {
  Pod,
  Workload,
  Service,
  RuntimeRisk,
  RiskCategory,
  RiskLevel,
  RiskSubject,
  Container,
} from '@aicc/models';

export const DANGEROUS_CAPABILITIES: ReadonlySet<string> = new Set([
  'NET_RAW',
  'NET_ADMIN',
  'SYS_ADMIN',
  'SYS_MODULE',
  'SYS_PTRACE',
  'SYS_RAWIO',
  'SYS_BOOT',
  'SYS_TIME',
  'SYSLOG',
  'MKNOD',
  'AUDIT_WRITE',
  'DAC_READ_SEARCH',
  'SETFCAP',
  'SYS_RESOURCE',
  'ALL',
]);

export const SENSITIVE_HOST_PATHS: ReadonlySet<string> = new Set([
  '/',
  '/etc',
  '/var/run/docker.sock',
  '/var/lib/kubelet',
  '/proc',
  '/sys',
  '/root',
  '/var/log',
]);

export interface RuleContext {
  tenantId: string;
  clusterId: string;
  clusterName: string;
}

export interface Rule {
  id: string;
  name: string;
  category: RiskCategory;
  /** Default level when the rule fires. Some rules escalate based on context. */
  level: RiskLevel;
  /** Default severity for incident correlation. */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  remediation: string;
  references: string[];
  evaluate(ctx: RuleContext, input: RuleInput): RuntimeRisk[];
}

export interface RuleInput {
  pods: Pod[];
  workloads: Workload[];
  services: Service[];
}

function makeRisk(args: {
  ctx: RuleContext;
  rule: Rule;
  subject: RiskSubject;
  subjectKind: string;
  subjectName: string;
  namespace: string;
  message: string;
  evidencePath?: string;
  evidenceValue?: string | number | boolean | null;
  level?: RiskLevel;
}): RuntimeRisk {
  return {
    id: crypto.randomUUID(),
    tenantId: args.ctx.tenantId,
    clusterId: args.ctx.clusterId,
    clusterName: args.ctx.clusterName,
    namespace: args.namespace,
    subject: args.subject,
    subjectKind: args.subjectKind,
    subjectName: args.subjectName,
    ruleId: args.rule.id,
    ruleName: args.rule.name,
    category: args.rule.category,
    level: args.level ?? args.rule.level,
    severity: args.rule.severity,
    message: args.message,
    evidencePath: args.evidencePath,
    evidenceValue: args.evidenceValue ?? null,
    remediation: args.rule.remediation,
    references: args.rule.references,
    detectedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

const CIS_K8S = 'https://www.cisecurity.org/benchmark/kubernetes';
const POD_SECURITY = 'https://kubernetes.io/docs/concepts/security/pod-security-standards/';

// ---- Rule 1: privileged container -----------------------------------

const privilegedRule: Rule = {
  id: 'AICC-RT-001',
  name: 'Privileged container',
  category: 'privileged_container',
  level: 'critical',
  severity: 'critical',
  remediation: 'Drop `securityContext.privileged: true` and use a narrowly-scoped `capabilities` set instead.',
  references: [`${CIS_K8S}#5-2-1`, POD_SECURITY],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        if (c.privileged) {
          out.push(makeRisk({
            ctx, rule: privilegedRule,
            subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
            message: `Container ${c.name} runs in privileged mode`,
            evidencePath: `pod.spec.containers[${c.name}].securityContext.privileged`,
            evidenceValue: true,
          }));
        }
      }
    }
    return out;
  },
};

// ---- Rule 2: hostPath volume ----------------------------------------

const hostPathRule: Rule = {
  id: 'AICC-RT-002',
  name: 'hostPath volume mount',
  category: 'host_path_volume',
  level: 'high',
  severity: 'high',
  remediation: 'Avoid `hostPath` mounts. Use `emptyDir`, `CSI`, or a projected volume for required data.',
  references: [`${CIS_K8S}#5-2-2`],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        for (const hp of c.hostPaths) {
          const sensitive = SENSITIVE_HOST_PATHS.has(hp);
          out.push(makeRisk({
            ctx, rule: hostPathRule,
            subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
            message: sensitive
              ? `Container ${c.name} mounts sensitive hostPath ${hp}`
              : `Container ${c.name} mounts hostPath ${hp}`,
            evidencePath: `pod.spec.containers[${c.name}].volumeMounts[hostPath=${hp}]`,
            evidenceValue: hp,
            level: sensitive ? 'critical' : 'high',
            severity: sensitive ? 'critical' : 'high',
          }));
        }
      }
    }
    return out;
  },
};

// ---- Rule 3: root user ----------------------------------------------

const rootUserRule: Rule = {
  id: 'AICC-RT-003',
  name: 'Root user execution',
  category: 'root_user',
  level: 'high',
  severity: 'high',
  remediation: 'Set `securityContext.runAsNonRoot: true` and `runAsUser: <non-zero>` (or use a `runAsUser` from your platform range).',
  references: [`${CIS_K8S}#5-2-6`, POD_SECURITY],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        if (c.runAsRoot) {
          out.push(makeRisk({
            ctx, rule: rootUserRule,
            subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
            message: `Container ${c.name} runs as root (uid 0)`,
            evidencePath: `pod.spec.containers[${c.name}].securityContext.runAsNonRoot`,
            evidenceValue: false,
          }));
        }
      }
    }
    return out;
  },
};

// ---- Rule 4: dangerous capability ----------------------------------

const dangerousCapRule: Rule = {
  id: 'AICC-RT-004',
  name: 'Dangerous Linux capability',
  category: 'dangerous_capability',
  level: 'high',
  severity: 'high',
  remediation: 'Drop the dangerous capability. If required, use `capabilities.add` with the minimal set.',
  references: [`${CIS_K8S}#5-2-8`, POD_SECURITY],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        for (const cap of c.addedCapabilities) {
          if (DANGEROUS_CAPABILITIES.has(cap)) {
            out.push(makeRisk({
              ctx, rule: dangerousCapRule,
              subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
              message: `Container ${c.name} adds dangerous capability ${cap}`,
              evidencePath: `pod.spec.containers[${c.name}].securityContext.capabilities.add`,
              evidenceValue: cap,
              level: cap === 'SYS_ADMIN' || cap === 'ALL' ? 'critical' : 'high',
            }));
          }
        }
      }
    }
    return out;
  },
};

// ---- Rule 5: weak SecurityContext -----------------------------------

const securityContextRule: Rule = {
  id: 'AICC-RT-005',
  name: 'Weak or missing SecurityContext',
  category: 'unsafe_security_context',
  level: 'medium',
  severity: 'medium',
  remediation: 'Set `securityContext.runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and drop all capabilities.',
  references: [POD_SECURITY],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      // Heuristic: a container is considered "weak" if it doesn't
      // explicitly set runAsNonRoot and the pod is not in a
      // system namespace. We surface one finding per pod.
      const isSystemNs = ['kube-system', 'kube-public', 'kube-node-lease'].includes(pod.namespace);
      if (isSystemNs) continue;
      const anyExplicit = pod.containers.some((c: Container) => !c.runAsRoot);
      if (anyExplicit) continue;
      out.push(makeRisk({
        ctx, rule: securityContextRule,
        subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
        message: 'Pod does not declare a hardened SecurityContext (runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation).',
        evidencePath: 'pod.spec.securityContext',
        evidenceValue: null,
      }));
    }
    return out;
  },
};

// ---- Rule 6: ServiceAccount risk -----------------------------------

const serviceAccountRule: Rule = {
  id: 'AICC-RT-006',
  name: 'Risky ServiceAccount usage',
  category: 'service_account_risk',
  level: 'medium',
  severity: 'medium',
  remediation: 'Bind a dedicated ServiceAccount with `automountServiceAccountToken: false` and minimal RBAC. Never use the `default` SA in production.',
  references: [`${CIS_K8S}#5-1-5`],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      const sa = pod.serviceAccount ?? 'default';
      if (sa === 'default' && pod.namespace !== 'kube-system' && pod.namespace !== 'kube-public') {
        out.push(makeRisk({
          ctx, rule: serviceAccountRule,
          subject: 'service_account', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
          message: 'Pod uses the `default` ServiceAccount',
          evidencePath: 'pod.spec.serviceAccountName',
          evidenceValue: sa,
          level: 'medium',
        }));
      }
    }
    void input;
    return out;
  },
};

// ---- Rule 7: RBAC risk ---------------------------------------------

const rbacRule: Rule = {
  id: 'AICC-RT-007',
  name: 'Risky RBAC binding',
  category: 'rbac_risk',
  level: 'high',
  severity: 'high',
  remediation: 'Replace `cluster-admin` with a namespace-scoped `Role`. Review ClusterRole grants; prefer individual verbs.',
  references: [`${CIS_K8S}#5-1-3`],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    // The fixture inventory doesn't include RoleBindings; this
    // rule is implemented as a stub that returns no findings in
    // Sprint 4. Sprint 5 will extend the inventory to surface
    // RoleBindings / ClusterRoleBindings.
    void input;
    // Mark the rule "evaluated" by emitting a no-op log signal
    // when needed; the engine already counts rules fired.
    return out;
  },
};

// ---- Rule 8: missing resource limits -------------------------------

const resourceLimitRule: Rule = {
  id: 'AICC-RT-008',
  name: 'Missing resource limits',
  category: 'resource_limits_missing',
  level: 'low',
  severity: 'low',
  remediation: 'Set CPU and memory `limits` on every container. Consider Vertical Pod Autoscaler for recommendation.',
  references: [`${CIS_K8S}#5-7-1`],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        if (c.resources.cpuLimitsMillicores === 0 || c.resources.memoryLimitsBytes === 0) {
          out.push(makeRisk({
            ctx, rule: resourceLimitRule,
            subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
            message: `Container ${c.name} has no CPU or memory limit`,
            evidencePath: `pod.spec.containers[${c.name}].resources.limits`,
            evidenceValue: null,
          }));
        }
      }
    }
    return out;
  },
};

// ---- Rule 9: image digest missing (AICC extension) ----------------

const imageDigestRule: Rule = {
  id: 'AICC-RT-009',
  name: 'Image tag is not pinned to a digest',
  category: 'image_risk',
  level: 'medium',
  severity: 'medium',
  remediation: 'Pin the image by digest (sha256:...) and add a supply-chain verification step (cosign / Kyverno).',
  references: ['https://kubernetes.io/docs/concepts/containers/images/'],
  evaluate(ctx, input) {
    const out: RuntimeRisk[] = [];
    for (const pod of input.pods) {
      for (const c of pod.containers) {
        if (!c.imageDigest) {
          out.push(makeRisk({
            ctx, rule: imageDigestRule,
            subject: 'pod', subjectKind: 'Pod', subjectName: pod.name, namespace: pod.namespace,
            message: `Container ${c.name} uses mutable image tag (${c.image})`,
            evidencePath: `pod.spec.containers[${c.name}].image`,
            evidenceValue: c.image,
          }));
        }
      }
    }
    return out;
  },
};

export const RULES: Rule[] = [
  privilegedRule,
  hostPathRule,
  rootUserRule,
  dangerousCapRule,
  securityContextRule,
  serviceAccountRule,
  rbacRule,
  resourceLimitRule,
  imageDigestRule,
];

export function listRules(): Rule[] {
  return RULES;
}
