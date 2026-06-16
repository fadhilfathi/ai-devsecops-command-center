/**
 * Runtime Security Engine.
 *
 * Pure function layer that takes a tenant / cluster inventory
 * snapshot, evaluates the rules, and produces findings + a
 * rollup `RuntimeSecurityReport`.
 */
import { randomUUID } from 'node:crypto';
import type {
  Pod,
  Workload,
  Service,
  RuntimeRisk,
  RuntimeSecurityReport,
  RiskLevel,
} from '@aicc/models';
import { RULES, type RuleInput, type RuleContext, type Rule } from './rules.js';

export interface RuntimeSecurityEngine {
  listRules(): Rule[];
  evaluate(input: RuntimeSecurityInput): RuntimeRisk[];
  report(input: RuntimeSecurityInput, windowStart: string, windowEnd: string): RuntimeSecurityReport;
}

export interface RuntimeSecurityInput {
  tenantId: string;
  clusterId: string;
  clusterName: string;
  pods: Pod[];
  workloads: Workload[];
  services: Service[];
}

function levelWeight(level: RiskLevel): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[level];
}

function rollupLevel(findings: RuntimeRisk[]): RiskLevel {
  if (findings.some((f) => f.level === 'critical')) return 'critical';
  if (findings.some((f) => f.level === 'high')) return 'high';
  if (findings.some((f) => f.level === 'medium')) return 'medium';
  if (findings.length > 0) return 'low';
  return 'low';
}

function scoreFor(findings: RuntimeRisk[]): number {
  if (findings.length === 0) return 100;
  let s = 100;
  for (const f of findings) {
    s -= 4 * levelWeight(f.level);
  }
  return Math.max(0, Math.min(100, Math.round(s)));
}

export function buildRuntimeSecurityEngine(): RuntimeSecurityEngine {
  return {
    listRules() {
      return RULES;
    },
    evaluate(input) {
      const ctx: RuleContext = {
        tenantId: input.tenantId,
        clusterId: input.clusterId,
        clusterName: input.clusterName,
      };
      const ruleInput: RuleInput = {
        pods: input.pods,
        workloads: input.workloads,
        services: input.services,
      };
      const out: RuntimeRisk[] = [];
      for (const rule of RULES) {
        try {
          out.push(...rule.evaluate(ctx, ruleInput));
        } catch (err) {
          // A buggy rule should never break the engine.
          // eslint-disable-next-line no-console
          console.error('[runtime-security] rule failed', { ruleId: rule.id, err });
        }
      }
      return out;
    },
    report(input, windowStart, windowEnd) {
      const findings = this.evaluate(input);
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      const categoryCounts: Record<string, number> = {};
      for (const f of findings) {
        counts[f.level] = (counts[f.level] ?? 0) + 1;
        categoryCounts[f.category] = (categoryCounts[f.category] ?? 0) + 1;
      }

      // Top recommendations: one per (rule) with the most findings.
      const recMap = new Map<string, { title: string; detail: string; level: RiskLevel; affectedCount: number }>();
      for (const f of findings) {
        const existing = recMap.get(f.ruleId);
        if (existing) {
          existing.affectedCount += 1;
          continue;
        }
        recMap.set(f.ruleId, {
          title: `Fix: ${f.ruleName}`,
          detail: f.remediation,
          level: f.level,
          affectedCount: 1,
        });
      }
      const recommendations = Array.from(recMap.values())
        .sort((a, b) => levelWeight(b.level) - levelWeight(a.level))
        .slice(0, 10)
        .map((r) => ({ ...r, id: randomUUID() }));

      return {
        id: randomUUID(),
        tenantId: input.tenantId,
        clusterId: input.clusterId,
        windowStart,
        windowEnd,
        riskLevel: rollupLevel(findings),
        score: scoreFor(findings),
        counts,
        categoryCounts,
        findings,
        recommendations,
        generatedAt: new Date().toISOString(),
      };
    },
  };
}
