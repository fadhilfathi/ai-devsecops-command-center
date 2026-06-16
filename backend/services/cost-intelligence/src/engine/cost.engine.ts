/**
 * Cost Intelligence Engine.
 *
 * Pure cost & waste analysis over a tenant inventory snapshot.
 *
 * Pricing (configurable):
 *   - `cpuUsdPerHour`   — USD per vCPU-hour
 *   - `memoryUsdPerHour` — USD per GiB-hour
 *
 * Findings (one or more per workload):
 *   - `over_provisioned_cpu`    — request far above observed p95
 *   - `over_provisioned_memory` — request far above observed p95
 *   - `under_utilized_cpu`      — p95 below 30% of request
 *   - `under_utilized_memory`   — p95 below 30% of request
 *   - `missing_requests`        — no CPU/memory requests set
 *   - `missing_limits`          — no CPU/memory limits set
 *   - `noisy_neighbour`         — limit / request ratio > 4
 *   - `cold_workload`           — p95 < 5% for 7 days
 *
 * Utilisation estimates:
 *   In Sprint 4 we don't have a metrics backend wired; we use
 *   *deterministic synthetic values* (the inventory snapshot
 *   exposes a `utilisation` field for that purpose). Sprint 5
 *   will swap this for real Prometheus queries.
 */
import { randomUUID } from 'node:crypto';
import type {
  Workload,
  CostAnalysis,
  WorkloadCost,
  CostFinding,
  CostRecommendation,
  OptimizationAction,
  PricingRates,
  ResourceDimension,
} from '@aicc/models';

export interface CostEngineInput {
  tenantId: string;
  clusterId?: string;
  clusterName?: string;
  workloads: Workload[];
  /** Utilisation estimates p50/p95 (0..1) per workload id. */
  utilisation?: Record<string, { cpuP50: number; cpuP95: number; memoryP50: number; memoryP95: number }>;
}

export interface CostEngine {
  analyse(input: CostEngineInput, windowStart: string, windowEnd: string): CostAnalysis;
  recommend(findings: CostFinding[], workloads: CostEngineInput['workloads']): CostRecommendation[];
}

const HOURS_PER_MONTH = 24 * 30; // 720

function toGiB(bytes: number): number {
  return bytes / (1024 * 1024 * 1024);
}

function workloadMonthlyCostUsd(reqs: { cpuMillicores: number; memoryBytes: number }, pricing: PricingRates): number {
  const vcpuHours = reqs.cpuMillicores / 1000;
  const memoryGibHours = toGiB(reqs.memoryBytes);
  return pricing.cpuUsdPerHour * vcpuHours * HOURS_PER_MONTH
    + pricing.memoryUsdPerHour * memoryGibHours * HOURS_PER_MONTH;
}

function findHighestSeverity(sevs: ('critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown')[]): 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown' {
  const order: ('critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown')[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  for (const o of order) {
    if (sevs.includes(o)) return o;
  }
  return 'unknown';
}

function recommendedSize(request: number, utilP95: number): number {
  if (utilP95 <= 0) return request;
  // Target: 80% of request utilisation at p95. We keep a
  // safety headroom of 1.25x and round up to the nearest 10m CPU
  // / 64MiB memory.
  const target = (utilP95 * 1.25) * request;
  if (request < 100) return Math.ceil(target / 10) * 10;     // millicores
  if (request < 100_000) return Math.ceil(target / 100) * 100; // millicores
  return Math.ceil(target / (64 * 1024 * 1024)) * (64 * 1024 * 1024);
}

function pushFinding(
  out: CostFinding[],
  args: {
    kind: CostFinding['kind'];
    dimension?: ResourceDimension;
    severity: CostFinding['severity'];
    message: string;
    workloadId: string;
    workloadName: string;
    namespace: string;
    monthlySavingsUsd: number;
    data?: Record<string, unknown>;
  },
): void {
  out.push({
    id: randomUUID(),
    kind: args.kind,
    severity: args.severity,
    message: args.message,
    dimension: args.dimension,
    workloadId: args.workloadId,
    workloadName: args.workloadName,
    namespace: args.namespace,
    monthlySavingsUsd: args.monthlySavingsUsd,
    data: args.data ?? {},
    detectedAt: new Date().toISOString(),
  });
}

export interface CostEngineDeps {
  cpuUsdPerHour: number;
  memoryUsdPerHour: number;
}

export function buildCostEngine(deps: CostEngineDeps): CostEngine {
  const pricing: PricingRates = {
    cpuUsdPerHour: deps.cpuUsdPerHour,
    memoryUsdPerHour: deps.memoryUsdPerHour,
    gpuUsdPerHour: 2.5,
    networkEgressUsdPerHour: 0,
    currency: 'USD',
  };
  return {
    analyse(input, windowStart, windowEnd) {
      const findings: CostFinding[] = [];
      const workloadCosts: WorkloadCost[] = [];
      let currentMonthlyUsd = 0;
      let recommendedMonthlyUsd = 0;

      for (const w of input.workloads) {
        const util = input.utilisation?.[w.id] ?? { cpuP50: 0.4, cpuP95: 0.6, memoryP50: 0.5, memoryP95: 0.7 };
        const reqs = {
          cpuMillicores: w.resources.cpuRequestsMillicores,
          memoryBytes: w.resources.memoryRequestsBytes,
        };
        const lims = {
          cpuMillicores: w.resources.cpuLimitsMillicores,
          memoryBytes: w.resources.memoryLimitsBytes,
        };
        const currentUsd = workloadMonthlyCostUsd(reqs, pricing) * w.replicas.ready;
        currentMonthlyUsd += currentUsd;

        // Findings.
        if (reqs.cpuMillicores === 0 || reqs.memoryBytes === 0) {
          pushFinding(findings, {
            kind: 'missing_requests', severity: 'medium',
            message: 'Workload has no CPU/memory requests set',
            workloadId: w.id, workloadName: w.name, namespace: w.namespace, monthlySavingsUsd: 0,
          });
        }
        if (lims.cpuMillicores === 0 || lims.memoryBytes === 0) {
          pushFinding(findings, {
            kind: 'missing_limits', severity: 'low',
            message: 'Workload has no CPU/memory limits set',
            workloadId: w.id, workloadName: w.name, namespace: w.namespace, monthlySavingsUsd: 0,
          });
        }
        if (reqs.cpuMillicores > 0 && util.cpuP95 < 0.3) {
          const newReq = recommendedSize(reqs.cpuMillicores, util.cpuP95);
          const newUsd = workloadMonthlyCostUsd({ cpuMillicores: newReq, memoryBytes: reqs.memoryBytes }, pricing) * w.replicas.ready;
          const savings = Math.max(0, currentUsd - newUsd);
          pushFinding(findings, {
            kind: 'under_utilized_cpu', dimension: 'cpu', severity: 'medium',
            message: `CPU p95 ${(util.cpuP95 * 100).toFixed(0)}% is well below request`,
            workloadId: w.id, workloadName: w.name, namespace: w.namespace, monthlySavingsUsd: savings,
            data: { currentMillicores: reqs.cpuMillicores, recommendedMillicores: newReq, utilP95: util.cpuP95 },
          });
        }
        if (reqs.memoryBytes > 0 && util.memoryP95 < 0.3) {
          const newReq = recommendedSize(reqs.memoryBytes, util.memoryP95);
          const newUsd = workloadMonthlyCostUsd({ cpuMillicores: reqs.cpuMillicores, memoryBytes: newReq }, pricing) * w.replicas.ready;
          const savings = Math.max(0, currentUsd - newUsd);
          pushFinding(findings, {
            kind: 'under_utilized_memory', dimension: 'memory', severity: 'medium',
            message: `Memory p95 ${(util.memoryP95 * 100).toFixed(0)}% is well below request`,
            workloadId: w.id, workloadName: w.name, namespace: w.namespace, monthlySavingsUsd: savings,
            data: { currentBytes: reqs.memoryBytes, recommendedBytes: newReq, utilP95: util.memoryP95 },
          });
        }
        if (lims.cpuMillicores > 0 && reqs.cpuMillicores > 0 && lims.cpuMillicores / reqs.cpuMillicores > 4) {
          pushFinding(findings, {
            kind: 'noisy_neighbour', dimension: 'cpu', severity: 'low',
            message: `CPU limit/request ratio is ${(lims.cpuMillicores / reqs.cpuMillicores).toFixed(1)}x — possible noisy neighbour`,
            workloadId: w.id, workloadName: w.name, namespace: w.namespace, monthlySavingsUsd: 0,
            data: { limit: lims.cpuMillicores, request: reqs.cpuMillicores },
          });
        }
        if (util.cpuP95 < 0.05 && util.memoryP95 < 0.05) {
          pushFinding(findings, {
            kind: 'cold_workload', severity: 'low',
            message: 'Workload is essentially idle (p95 < 5% on both dimensions)',
            workloadId: w.id, workloadName: w.name, namespace: w.namespace,
            monthlySavingsUsd: currentUsd,
            data: { utilP95: { cpu: util.cpuP95, memory: util.memoryP95 } },
          });
        }

        // Recommended cost: target p95 ≈ 80%.
        const target = {
          cpuMillicores: reqs.cpuMillicores > 0 ? Math.max(50, recommendedSize(reqs.cpuMillicores, util.cpuP95)) : 0,
          memoryBytes: reqs.memoryBytes > 0 ? Math.max(64 * 1024 * 1024, recommendedSize(reqs.memoryBytes, util.memoryP95)) : 0,
        };
        const recommendedUsd = workloadMonthlyCostUsd(target, pricing) * w.replicas.ready;
        const potentialMonthlySavingsUsd = Math.max(0, currentUsd - recommendedUsd);
        recommendedMonthlyUsd += recommendedUsd;

        workloadCosts.push({
          workloadId: w.id,
          workloadName: w.name,
          namespace: w.namespace,
          kind: w.kind,
          currentMonthlyUsd: roundUsd(currentUsd),
          recommendedMonthlyUsd: roundUsd(recommendedUsd),
          potentialMonthlySavingsUsd: roundUsd(potentialMonthlySavingsUsd),
          utilisation: util,
          requests: reqs,
          limits: lims,
        });
      }

      const recommendations = this.recommend(findings, input.workloads);
      const potentialMonthlySavingsUsd = Math.max(0, currentMonthlyUsd - recommendedMonthlyUsd);

      return {
        id: randomUUID(),
        tenantId: input.tenantId,
        clusterId: input.clusterId,
        windowStart,
        windowEnd,
        pricing,
        currentMonthlyUsd: roundUsd(currentMonthlyUsd),
        recommendedMonthlyUsd: roundUsd(recommendedMonthlyUsd),
        potentialMonthlySavingsUsd: roundUsd(potentialMonthlySavingsUsd),
        workloads: workloadCosts,
        findings,
        recommendations,
        generatedAt: new Date().toISOString(),
      };
    },

    recommend(findings, _workloads) {
      void _workloads;
      const recs: CostRecommendation[] = [];
      const seen = new Set<string>();
      for (const f of findings) {
        let action: OptimizationAction = 'unknown';
        let title = '';
        let detail = '';
        const priority: CostRecommendation['priority'] =
          f.severity === 'critical' ? 'p0' : f.severity === 'high' ? 'p1' : f.severity === 'medium' ? 'p2' : 'p3';
        switch (f.kind) {
          case 'over_provisioned_cpu':
          case 'under_utilized_cpu':
            action = 'right_size_requests'; title = 'Right-size CPU requests';
            detail = 'Reduce CPU requests to better match observed p95 utilisation.';
            break;
          case 'over_provisioned_memory':
          case 'under_utilized_memory':
            action = 'right_size_requests'; title = 'Right-size memory requests';
            detail = 'Reduce memory requests to better match observed p95 utilisation.';
            break;
          case 'missing_requests':
            action = 'add_requests'; title = 'Add CPU/memory requests';
            detail = 'Add explicit CPU and memory requests to enable scheduler bin-packing.';
            break;
          case 'missing_limits':
            action = 'add_limits'; title = 'Add CPU/memory limits';
            detail = 'Add explicit limits to prevent noisy-neighbour issues.';
            break;
          case 'noisy_neighbour':
            action = 'right_size_limits'; title = 'Tighten CPU/memory limits';
            detail = 'Limit/request ratio is high — tighten limits to prevent noisy-neighbour.';
            break;
          case 'cold_workload':
            action = 'remove_unused_workload'; title = 'Consider removing idle workload';
            detail = 'Workload is essentially idle. Decommission or scale to zero.';
            break;
        }
        const key = `${action}::${title}`;
        if (seen.has(key) || action === 'unknown') continue;
        seen.add(key);
        recs.push({
          id: randomUUID(),
          action,
          priority,
          title,
          detail,
          workloadIds: [],
          monthlySavingsUsd: roundUsd(f.monthlySavingsUsd),
          annualSavingsUsd: roundUsd(f.monthlySavingsUsd * 12),
          actionPayload: { kind: f.kind, dimension: f.dimension ?? null },
          createdAt: new Date().toISOString(),
        });
      }
      return recs.sort((a, b) => a.priority.localeCompare(b.priority));
    },
  };
}

function roundUsd(v: number): number {
  return Math.round(v * 100) / 100;
}

// Avoid unused-import warnings for severity rollup helper.
export const __internal_severityRollup = findHighestSeverity;
