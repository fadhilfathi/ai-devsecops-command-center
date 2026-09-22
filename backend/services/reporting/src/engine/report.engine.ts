/**
 * Report Engine.
 *
 * Pure functions that produce the six canonical infrastructure
 * reports. Each report is a structured `Report` object with:
 *   - `id`              stable identifier
 *   - `kind`            one of the canonical ReportKind values
 *   - `title`           human-readable title
 *   - `tenantId`        tenant scope
 *   - `windowStart` /   ISO-8601 window
 *   - `windowEnd`
 *   - `summary`         one-paragraph TL;DR
 *   - `sections`        ordered ReportSection list
 *   - `tables`          structured tables (for PDF / Excel)
 *   - `generatedAt`
 *
 * The same Report can be rendered to JSON, Markdown, or PDF by
 * the formatter layer in `routes/reports.ts`.
 */
import { randomUUID } from 'node:crypto';
import type {
  Cluster,
  Namespace,
  Workload,
  Pod,
  Service,
  Deployment,
  StatefulSet,
  DaemonSet,
  Ingress,
  InfrastructureHealth,
  RuntimeSecurityReport,
  CostAnalysis,
  TopologyGraph,
  RuntimeRisk,
  CostFinding,
  CostRecommendation,
} from '@aicc/models';
import type { UUID } from '@aicc/shared';

export type ReportKind =
  | 'cluster_health'
  | 'infrastructure_risk'
  | 'runtime_security'
  | 'cost_optimization'
  | 'topology'
  | 'executive_summary';

export interface ReportTable {
  title: string;
  columns: string[];
  rows: Array<Array<string | number | null>>;
}

export interface ReportSection {
  title: string;
  body: string;
  bullets?: string[];
}

export interface ReportChart {
  title: string;
  items: Array<{ label: string; value: number }>;
}

export interface Report {
  id: string;
  kind: ReportKind;
  title: string;
  tenantId: UUID;
  clusterId?: string;
  windowStart: string;
  windowEnd: string;
  summary: string;
  sections: ReportSection[];
  tables: ReportTable[];
  charts?: ReportChart[];
  generatedAt: string;
}

export interface ReportEngineInput {
  clusters: Cluster[];
  namespaces: Namespace[];
  workloads: Workload[];
  pods: Pod[];
  services: Service[];
  deployments: Deployment[];
  statefulsets: StatefulSet[];
  daemonsets: DaemonSet[];
  ingresses: Ingress[];
  health: InfrastructureHealth[];
  runtimeReport: RuntimeSecurityReport | undefined;
  costAnalysis: CostAnalysis | undefined;
  topology: TopologyGraph | undefined;
}

export interface ReportEngine {
  clusterHealth(input: ReportEngineInput): Report;
  infrastructureRisk(input: ReportEngineInput): Report;
  runtimeSecurity(input: ReportEngineInput): Report;
  costOptimization(input: ReportEngineInput): Report;
  topology(input: ReportEngineInput): Report;
  executiveSummary(input: ReportEngineInput): Report;
}

function isoWindow(days = 30): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

function fmt(n: number): string {
  return Number.isFinite(n) ? Math.round(n).toLocaleString('en-US') : '—';
}

function money(n: number): string {
  return Number.isFinite(n) ? `$${Math.round(n).toLocaleString('en-US')}` : '—';
}

export function buildReportEngine(): ReportEngine {
  return {
    clusterHealth(input) {
      const window = isoWindow();
      const clusters = input.clusters;
      const sections: ReportSection[] = [];
      const tables: ReportTable[] = [];
      const clusterHealth = input.health.filter((h) => h.scope === 'cluster');
      sections.push({
        title: 'Overview',
        body: `${clusters.length} cluster(s) on file; ${clusterHealth.length} cluster health record(s) present.`,
        bullets: clusterHealth.map(
          (h) =>
            `${h.subject.name}: ${h.score.score}/100 (band ${h.score.band}, status ${h.score.status}) — ${h.score.counts.critical} critical, ${h.score.counts.high} high`,
        ),
      });
      tables.push({
        title: 'Cluster health summary',
        columns: ['Cluster', 'Score', 'Band', 'Status', 'Critical', 'High', 'Medium', 'Low'],
        rows: clusterHealth.map((h) => [
          h.subject.name,
          h.score.score,
          h.score.band,
          h.score.status,
          h.score.counts.critical,
          h.score.counts.high,
          h.score.counts.medium,
          h.score.counts.low,
        ]),
      });
      const allIssues = clusterHealth.flatMap((h) => h.issues);
      tables.push({
        title: 'Top issues',
        columns: ['Cluster', 'Kind', 'Severity', 'Subject', 'Message'],
        rows: allIssues
          .slice(0, 25)
          .map((i) => [
            i.subject.clusterId ?? '—',
            i.kind,
            i.severity,
            `${i.subject.kind}/${i.subject.name}`,
            i.message,
          ]),
      });
      const allRecs = clusterHealth.flatMap((h) => h.recommendations);
      sections.push({
        title: 'Top recommendations',
        body: `${allRecs.length} recommendation(s) generated.`,
        bullets: allRecs
          .slice(0, 10)
          .map((r) => `[${r.priority.toUpperCase()}] ${r.title} — ${r.detail}`),
      });
      const severityCounts = clusterHealth.reduce(
        (a, h) => ({
          critical: a.critical + h.score.counts.critical,
          high: a.high + h.score.counts.high,
          medium: a.medium + h.score.counts.medium,
          low: a.low + h.score.counts.low,
        }),
        { critical: 0, high: 0, medium: 0, low: 0 },
      );
      const charts =
        clusterHealth.length > 0
          ? [
              {
                title: 'Findings by severity',
                items: [
                  { label: 'Critical', value: severityCounts.critical },
                  { label: 'High', value: severityCounts.high },
                  { label: 'Medium', value: severityCounts.medium },
                  { label: 'Low', value: severityCounts.low },
                ],
              },
            ]
          : undefined;
      return {
        id: randomUUID(),
        kind: 'cluster_health',
        title: 'Cluster Health Report',
        tenantId: clusters[0]?.tenantId ?? '',
        windowStart: window.start,
        windowEnd: window.end,
        summary: `${clusters.length} cluster(s) analysed; average score ${Math.round(clusterHealth.reduce((a, h) => a + h.score.score, 0) / Math.max(1, clusterHealth.length))}/100.`,
        sections,
        tables,
        charts,
        generatedAt: new Date().toISOString(),
      };
    },

    infrastructureRisk(input) {
      const window = isoWindow();
      const tables: ReportTable[] = [];
      const sections: ReportSection[] = [];
      const runtime = input.runtimeReport;
      const cost = input.costAnalysis;
      const health = input.health;
      const runtimeFindings: RuntimeRisk[] = runtime?.findings ?? [];
      const costFindings: CostFinding[] = cost?.findings ?? [];
      const allIssues = health.flatMap((h) => h.issues);
      sections.push({
        title: 'Risk summary',
        body: 'Aggregate risk across runtime security, cost, and cluster health.',
        bullets: [
          runtime
            ? `Runtime security: ${runtime.riskLevel} (score ${runtime.score}/100)`
            : 'Runtime security: no data',
          cost
            ? `Cost: $${fmt(cost.potentialMonthlySavingsUsd)}/mo potential savings across ${cost.workloads.length} workload(s)`
            : 'Cost: no data',
          `Cluster health: ${health.length} health record(s)`,
          `Open issues: ${allIssues.length}`,
        ],
      });
      tables.push({
        title: 'Runtime risks',
        columns: ['Rule', 'Level', 'Subject', 'Message'],
        rows: runtimeFindings
          .slice(0, 25)
          .map((r) => [
            `${r.ruleId} ${r.ruleName}`,
            r.level,
            `${r.namespace}/${r.subjectName}`,
            r.message,
          ]),
      });
      tables.push({
        title: 'Cost findings',
        columns: ['Kind', 'Severity', 'Subject', 'Monthly $', 'Message'],
        rows: costFindings
          .slice(0, 25)
          .map((f) => [
            f.kind,
            f.severity,
            `${f.namespace ?? '—'}/${f.workloadName ?? '—'}`,
            money(f.monthlySavingsUsd),
            f.message,
          ]),
      });
      const byLevel = new Map<string, number>();
      for (const f of runtimeFindings) byLevel.set(f.level, (byLevel.get(f.level) ?? 0) + 1);
      const charts =
        byLevel.size > 0
          ? [
              {
                title: 'Runtime findings by level',
                items: Array.from(byLevel.entries()).map(([label, value]) => ({ label, value })),
              },
            ]
          : undefined;
      return {
        id: randomUUID(),
        kind: 'infrastructure_risk',
        title: 'Infrastructure Risk Report',
        tenantId: runtime?.tenantId ?? cost?.tenantId ?? input.clusters[0]?.tenantId ?? '',
        windowStart: window.start,
        windowEnd: window.end,
        summary: `Combined infrastructure risk: ${runtimeFindings.length} runtime finding(s) + ${costFindings.length} cost finding(s) + ${allIssues.length} health issue(s).`,
        sections,
        tables,
        charts,
        generatedAt: new Date().toISOString(),
      };
    },

    runtimeSecurity(input) {
      const window = isoWindow(1);
      const r = input.runtimeReport;
      const sections: ReportSection[] = [];
      const tables: ReportTable[] = [];
      sections.push({
        title: 'Overview',
        body: r
          ? `Risk level ${r.riskLevel}; score ${r.score}/100.`
          : 'No runtime security data available.',
        bullets: r
          ? [
              `${r.counts.critical} critical, ${r.counts.high} high, ${r.counts.medium} medium, ${r.counts.low} low finding(s)`,
              `Top categories: ${
                Object.entries(r.categoryCounts)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 3)
                  .map(([k, v]) => `${k} (${v})`)
                  .join(', ') || '—'
              }`,
            ]
          : undefined,
      });
      if (r) {
        tables.push({
          title: 'Findings',
          columns: ['Rule', 'Level', 'Subject', 'Message'],
          rows: r.findings.map((f) => [
            `${f.ruleId} ${f.ruleName}`,
            f.level,
            `${f.namespace}/${f.subjectName}`,
            f.message,
          ]),
        });
        tables.push({
          title: 'Recommendations',
          columns: ['Title', 'Level', 'Affected'],
          rows: r.recommendations.map((rec) => [rec.title, rec.level, fmt(rec.affectedCount)]),
        });
      }
      const charts = r
        ? [
            {
              title: 'Findings by severity',
              items: [
                { label: 'Critical', value: r.counts.critical },
                { label: 'High', value: r.counts.high },
                { label: 'Medium', value: r.counts.medium },
                { label: 'Low', value: r.counts.low },
              ],
            },
          ]
        : undefined;
      return {
        id: randomUUID(),
        kind: 'runtime_security',
        title: 'Runtime Security Report',
        tenantId: r?.tenantId ?? input.clusters[0]?.tenantId ?? '',
        clusterId: r?.clusterId,
        windowStart: r?.windowStart ?? window.start,
        windowEnd: r?.windowEnd ?? window.end,
        summary: r
          ? `Runtime risk level ${r.riskLevel}; ${r.counts.critical + r.counts.high + r.counts.medium + r.counts.low} finding(s) across ${Object.keys(r.categoryCounts).length} categor${Object.keys(r.categoryCounts).length === 1 ? 'y' : 'ies'}.`
          : 'No runtime security data available.',
        sections,
        tables,
        charts,
        generatedAt: new Date().toISOString(),
      };
    },

    costOptimization(input) {
      const window = isoWindow(30);
      const c = input.costAnalysis;
      const sections: ReportSection[] = [];
      const tables: ReportTable[] = [];
      sections.push({
        title: 'Overview',
        body: c
          ? `Current ${money(c.currentMonthlyUsd)}/mo; recommended ${money(c.recommendedMonthlyUsd)}/mo.`
          : 'No cost data available.',
        bullets: c
          ? [
              `Potential monthly savings: ${money(c.potentialMonthlySavingsUsd)}`,
              `Annualised savings: ${money(c.potentialMonthlySavingsUsd * 12)}`,
              `Findings: ${c.findings.length}; recommendations: ${c.recommendations.length}`,
            ]
          : undefined,
      });
      if (c) {
        tables.push({
          title: 'Per-workload cost',
          columns: ['Workload', 'Namespace', 'Current $/mo', 'Recommended $/mo', 'Savings $/mo'],
          rows: c.workloads.map((w) => [
            w.workloadName,
            w.namespace,
            money(w.currentMonthlyUsd),
            money(w.recommendedMonthlyUsd),
            money(w.potentialMonthlySavingsUsd),
          ]),
        });
        tables.push({
          title: 'Findings',
          columns: ['Kind', 'Severity', 'Subject', 'Monthly $', 'Message'],
          rows: c.findings.map((f) => [
            f.kind,
            f.severity,
            `${f.namespace ?? '—'}/${f.workloadName ?? '—'}`,
            money(f.monthlySavingsUsd),
            f.message,
          ]),
        });
        tables.push({
          title: 'Recommendations',
          columns: ['Priority', 'Action', 'Title', 'Monthly $', 'Annual $'],
          rows: c.recommendations.map((r: CostRecommendation) => [
            r.priority.toUpperCase(),
            r.action,
            r.title,
            money(r.monthlySavingsUsd),
            money(r.annualSavingsUsd),
          ]),
        });
      }
      const byNamespace = new Map<string, number>();
      for (const w of c?.workloads ?? []) {
        byNamespace.set(w.namespace, (byNamespace.get(w.namespace) ?? 0) + w.currentMonthlyUsd);
      }
      const charts =
        byNamespace.size > 0
          ? [
              {
                title: 'Monthly cost by namespace',
                items: Array.from(byNamespace.entries()).map(([label, value]) => ({
                  label,
                  value: Math.round(value),
                })),
              },
            ]
          : undefined;
      return {
        id: randomUUID(),
        kind: 'cost_optimization',
        title: 'Cost Optimization Report',
        tenantId: c?.tenantId ?? input.clusters[0]?.tenantId ?? '',
        clusterId: c?.clusterId,
        windowStart: c?.windowStart ?? window.start,
        windowEnd: c?.windowEnd ?? window.end,
        summary: c
          ? `Save ${money(c.potentialMonthlySavingsUsd)}/mo (${Math.round((c.potentialMonthlySavingsUsd / Math.max(1, c.currentMonthlyUsd)) * 100)}% reduction) by applying ${c.recommendations.length} recommendation(s).`
          : 'No cost data available.',
        sections,
        tables,
        charts,
        generatedAt: new Date().toISOString(),
      };
    },

    topology(input) {
      const window = isoWindow();
      const t = input.topology;
      const sections: ReportSection[] = [];
      const tables: ReportTable[] = [];
      sections.push({
        title: 'Overview',
        body: t
          ? `${t.nodes.length} node(s) and ${t.edges.length} edge(s) in the topology graph.`
          : 'No topology data available.',
      });
      let charts: Report['charts'];
      if (t) {
        const byKind = new Map<string, number>();
        for (const n of t.nodes) byKind.set(n.kind, (byKind.get(n.kind) ?? 0) + 1);
        tables.push({
          title: 'Node distribution',
          columns: ['Kind', 'Count'],
          rows: Array.from(byKind.entries()).map(([k, v]) => [k, v]),
        });
        const byEdge = new Map<string, number>();
        for (const e of t.edges) byEdge.set(e.kind, (byEdge.get(e.kind) ?? 0) + 1);
        tables.push({
          title: 'Edge distribution',
          columns: ['Kind', 'Count'],
          rows: Array.from(byEdge.entries()).map(([k, v]) => [k, v]),
        });
        charts = [
          {
            title: 'Node distribution',
            items: Array.from(byKind.entries()).map(([label, value]) => ({ label, value })),
          },
        ];
      }
      return {
        id: randomUUID(),
        kind: 'topology',
        title: 'Topology Report',
        tenantId: t?.tenantId ?? input.clusters[0]?.tenantId ?? '',
        clusterId: t?.clusterId,
        windowStart: window.start,
        windowEnd: window.end,
        summary: t
          ? `Application graph with ${t.nodes.length} nodes and ${t.edges.length} edges.`
          : 'No topology data available.',
        sections,
        tables,
        charts,
        generatedAt: new Date().toISOString(),
      };
    },

    executiveSummary(input) {
      const window = isoWindow();
      const sections: ReportSection[] = [];
      const tables: ReportTable[] = [];
      const r = input.runtimeReport;
      const c = input.costAnalysis;
      const h = input.health.filter((x) => x.scope === 'cluster');
      const avgHealth =
        h.length === 0 ? 0 : Math.round(h.reduce((a, x) => a + x.score.score, 0) / h.length);
      sections.push({
        title: 'Executive overview',
        body: `Tenant posture: ${input.clusters.length} cluster(s), ${input.namespaces.length} namespace(s), ${input.workloads.length} workload(s), ${input.pods.length} pod(s).`,
        bullets: [
          `Average cluster health: ${avgHealth}/100`,
          r
            ? `Runtime security: ${r.riskLevel} (${r.counts.critical} critical, ${r.counts.high} high)`
            : 'Runtime security: no data',
          c
            ? `Monthly cost: ${money(c.currentMonthlyUsd)}; potential savings ${money(c.potentialMonthlySavingsUsd)}/mo`
            : 'Cost: no data',
          `Workload health: ${input.workloads.filter((w) => w.health === 'healthy').length} healthy / ${input.workloads.filter((w) => w.health !== 'healthy').length} unhealthy`,
        ],
      });
      tables.push({
        title: 'Cluster rollup',
        columns: ['Cluster', 'Provider', 'Nodes', 'CPU', 'Memory', 'Health'],
        rows: input.clusters.map((cl) => {
          const hs = h.find((x) => x.subject.clusterId === cl.id);
          return [
            cl.name,
            cl.provider,
            `${cl.readyNodes}/${cl.nodeCount}`,
            `${cl.totalCpuCores} cores`,
            `${Math.round(cl.totalMemoryBytes / 1024 ** 3)} GiB`,
            hs ? `${hs.score.score} (${hs.score.band})` : '—',
          ];
        }),
      });
      sections.push({
        title: 'Top risks',
        body: 'Prioritised by severity.',
        bullets: [
          ...(r
            ? r.findings
                .filter((f) => f.level === 'critical')
                .slice(0, 5)
                .map((f) => `[Runtime] ${f.message}`)
            : []),
          ...(c
            ? c.findings
                .filter((f) => f.severity === 'high' || f.severity === 'critical')
                .slice(0, 5)
                .map((f) => `[Cost] ${f.message}`)
            : []),
          ...h
            .flatMap((x) => x.issues)
            .filter((i) => i.severity === 'critical' || i.severity === 'high')
            .slice(0, 5)
            .map((i) => `[Health] ${i.message}`),
        ],
      });
      return {
        id: randomUUID(),
        kind: 'executive_summary',
        title: 'Executive Infrastructure Summary',
        tenantId: input.clusters[0]?.tenantId ?? '',
        windowStart: window.start,
        windowEnd: window.end,
        summary: `Posture: ${input.clusters.length} cluster(s), ${avgHealth}/100 avg health, ${r?.riskLevel ?? '—'} runtime risk, ${money(c?.currentMonthlyUsd ?? 0)}/mo cost.`,
        sections,
        tables,
        generatedAt: new Date().toISOString(),
      };
    },
  };
}
