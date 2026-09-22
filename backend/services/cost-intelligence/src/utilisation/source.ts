/**
 * Utilisation sources for the cost engine.
 *
 * The engine needs per-workload CPU/memory utilisation (p50/p95 as a
 * ratio of the request) to size recommendations. Two sources:
 *   - `buildSyntheticUtilisationSource` — deterministic placeholder
 *     values, used when no metrics backend is configured.
 *   - `buildPrometheusUtilisationSource` — real cAdvisor/kubelet
 *     metrics (`container_cpu_usage_seconds_total`,
 *     `container_memory_working_set_bytes`) queried from Prometheus,
 *     grouped by namespace to keep the query count low (one query
 *     per metric/quantile per namespace, not per workload).
 *
 * Both sources degrade gracefully: a workload with no resolvable
 * series is simply left out of the returned map, and the engine
 * falls back to its built-in defaults for that workload.
 */
import { z } from 'zod';
import type { Logger } from '@aicc/shared';
import type { Pod, Workload } from '@aicc/models';
import type { CostEngineInput } from '../engine/cost.engine.js';

export type Utilisation = NonNullable<CostEngineInput['utilisation']>[string];

export interface UtilisationSourceInput {
  tenantId: string;
  clusterId?: string;
  workloads: Workload[];
  pods: Pod[];
  windowStart: string;
  windowEnd: string;
}

export interface UtilisationFetchResult {
  utilisation: CostEngineInput['utilisation'];
  /** Where the returned values actually came from. */
  kind: 'prometheus' | 'synthetic';
}

export interface UtilisationSource {
  fetch(input: UtilisationSourceInput): Promise<UtilisationFetchResult>;
}

// ---------------------------------------------------------------------------
// Synthetic source — deterministic placeholder values (pre-Prometheus
// behaviour, unchanged).
// ---------------------------------------------------------------------------

export function buildSyntheticUtilisationSource(): UtilisationSource {
  return {
    async fetch(input) {
      const out: NonNullable<CostEngineInput['utilisation']> = {};
      for (const w of input.workloads) {
        out[w.id] = { cpuP50: 0.4, cpuP95: 0.6, memoryP50: 0.5, memoryP95: 0.7 };
      }
      return { utilisation: out, kind: 'synthetic' };
    },
  };
}

// ---------------------------------------------------------------------------
// Prometheus source
// ---------------------------------------------------------------------------

const PromResponseSchema = z.object({
  status: z.string(),
  data: z
    .object({
      resultType: z.string().optional(),
      result: z.array(
        z.object({
          metric: z.record(z.string(), z.string()).default({}),
          value: z.tuple([z.number(), z.string()]).optional(),
        }),
      ),
    })
    .optional(),
});

export interface PrometheusUtilisationSourceDeps {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  logger: Logger;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Escapes a value for safe interpolation inside a double-quoted PromQL
 * label matcher (`label="<value>"` or `label=~"<value>"`). Prevents
 * PromQL injection via namespace/pod/workload names sourced from
 * cluster inventory data. Strips control characters and escapes `\`
 * and `"` per PromQL string-literal rules.
 */
function promQuote(value: string): string {
  return (
    value
      // eslint-disable-next-line no-control-regex -- deliberately stripping control chars
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
  );
}

function windowMinutes(windowStart: string, windowEnd: string): string {
  const ms = Date.parse(windowEnd) - Date.parse(windowStart);
  const minutes = Math.max(5, Math.round(ms / 60_000));
  return `${minutes}m`;
}

interface WorkloadRegexEntry {
  workload: Workload;
  /** Real (unescaped-for-PromQL) regex, safe to feed straight into `new RegExp`. */
  regex: string;
  /** Whether `regex` came from known owned pods vs. the name-prefix fallback. */
  matchedOwnedPods: boolean;
}

/** Groups workloads by namespace and builds a pod-name regex per workload. */
function resolvePodRegexByNamespace(
  workloads: Workload[],
  pods: Pod[],
): Map<string, WorkloadRegexEntry[]> {
  const byNamespace = new Map<string, WorkloadRegexEntry[]>();
  for (const w of workloads) {
    const ownedPodNames = pods
      .filter((p) => p.namespace === w.namespace && p.ownerName === w.name)
      .map((p) => p.name);
    const regex =
      ownedPodNames.length > 0
        ? ownedPodNames.map(escapeRegex).join('|')
        : `^${escapeRegex(w.name)}-.*`;
    const list = byNamespace.get(w.namespace) ?? [];
    list.push({ workload: w, regex, matchedOwnedPods: ownedPodNames.length > 0 });
    byNamespace.set(w.namespace, list);
  }
  return byNamespace;
}

interface PodSum {
  [pod: string]: number;
}

async function runQuery(
  baseUrl: string,
  fetchImpl: typeof fetch,
  logger: Logger,
  query: string,
  time: string,
): Promise<PodSum> {
  const url = `${baseUrl.replace(/\/$/, '')}/api/v1/query?query=${encodeURIComponent(query)}&time=${encodeURIComponent(time)}`;
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) {
      logger.warn({ url, status: res.status }, 'prometheus query failed');
      return {};
    }
    const body = PromResponseSchema.parse(await res.json());
    if (body.status !== 'success' || !body.data) {
      logger.warn({ url, status: body.status }, 'prometheus query did not succeed');
      return {};
    }
    const out: PodSum = {};
    for (const r of body.data.result) {
      const pod = r.metric.pod;
      if (!pod || !r.value) continue;
      out[pod] = Number(r.value[1]);
    }
    return out;
  } catch (err) {
    logger.warn({ err, url }, 'prometheus query threw');
    return {};
  }
}

function clampRatio(v: number): number {
  if (!Number.isFinite(v) || v < 0) return 0;
  return Math.min(5, v);
}

export function buildPrometheusUtilisationSource(
  deps: PrometheusUtilisationSourceDeps,
): UtilisationSource {
  const { baseUrl, logger } = deps;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return {
    async fetch(input) {
      const out: NonNullable<CostEngineInput['utilisation']> = {};
      const byNamespace = resolvePodRegexByNamespace(input.workloads, input.pods);
      const window = windowMinutes(input.windowStart, input.windowEnd);
      const time = input.windowEnd;

      for (const [namespace, entries] of byNamespace) {
        const podRegex = entries.map((e) => promQuote(e.regex)).join('|');
        const namespaceQuoted = promQuote(namespace);
        const cpuBase = `sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="${namespaceQuoted}",pod=~"${podRegex}",container!="",container!="POD"}[5m]))[${window}:5m]`;
        const memBase = `sum by (pod) (container_memory_working_set_bytes{namespace="${namespaceQuoted}",pod=~"${podRegex}",container!="",container!="POD"})[${window}:5m]`;

        const [cpuP50, cpuP95, memP50, memP95] = await Promise.all([
          runQuery(baseUrl, fetchImpl, logger, `quantile_over_time(0.5, ${cpuBase})`, time),
          runQuery(baseUrl, fetchImpl, logger, `quantile_over_time(0.95, ${cpuBase})`, time),
          runQuery(baseUrl, fetchImpl, logger, `quantile_over_time(0.5, ${memBase})`, time),
          runQuery(baseUrl, fetchImpl, logger, `quantile_over_time(0.95, ${memBase})`, time),
        ]);

        for (const { workload, regex, matchedOwnedPods } of entries) {
          const podNames = Object.keys({ ...cpuP50, ...cpuP95, ...memP50, ...memP95 }).filter(
            (pod) => new RegExp(`^(${regex})$`).test(pod),
          );
          if (podNames.length === 0) continue;

          const podCount = matchedOwnedPods
            ? podNames.length
            : workload.replicas.ready || workload.replicas.desired || podNames.length;

          const sum = (m: PodSum): number => podNames.reduce((acc, p) => acc + (m[p] ?? 0), 0);
          const cpuReqTotal = (workload.resources.cpuRequestsMillicores / 1000) * podCount;
          const memReqTotal = workload.resources.memoryRequestsBytes * podCount;

          const cpuP50Ratio = cpuReqTotal > 0 ? clampRatio(sum(cpuP50) / cpuReqTotal) : undefined;
          const cpuP95Ratio = cpuReqTotal > 0 ? clampRatio(sum(cpuP95) / cpuReqTotal) : undefined;
          const memP50Ratio = memReqTotal > 0 ? clampRatio(sum(memP50) / memReqTotal) : undefined;
          const memP95Ratio = memReqTotal > 0 ? clampRatio(sum(memP95) / memReqTotal) : undefined;

          if (
            cpuP50Ratio === undefined ||
            cpuP95Ratio === undefined ||
            memP50Ratio === undefined ||
            memP95Ratio === undefined
          ) {
            continue;
          }

          out[workload.id] = {
            cpuP50: cpuP50Ratio,
            cpuP95: cpuP95Ratio,
            memoryP50: memP50Ratio,
            memoryP95: memP95Ratio,
          };
        }
      }

      return { utilisation: out, kind: Object.keys(out).length > 0 ? 'prometheus' : 'synthetic' };
    },
  };
}
