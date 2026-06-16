import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, fmtUsd, titleCase, fmtCpu, fmtBytes } from "@/lib/format";
import type { WorkloadCost, CostFinding, CostRecommendation } from "@/types/infrastructure";

/**
 * Cost Intelligence — current vs recommended monthly cost,
 * per-workload breakdown, findings, and recommendations.
 */
export function CostIntelligence() {
  const { data: analysis } = useFetch(api.costAnalysis, { items: [], total: 0 });
  const { data: workloads } = useFetch(api.costWorkloads, { items: [], total: 0 });
  const { data: findings } = useFetch(api.costFindings, { items: [], total: 0 });
  const { data: recommendations } = useFetch(api.costRecommendations, { items: [], total: 0 });
  const a = analysis.items[0];

  const workloadColumns: Column<WorkloadCost & { key: string }>[] = [
    { key: "name", header: "Workload", cell: (w) => w.workloadName },
    { key: "ns", header: "Namespace", cell: (w) => w.namespace },
    { key: "kind", header: "Kind", cell: (w) => <Badge variant="neutral">{w.kind}</Badge> },
    { key: "req", header: "Requests (cpu/mem)", cell: (w) => `${fmtCpu(w.requests.cpuMillicores)} / ${fmtBytes(w.requests.memoryBytes)}` },
    { key: "cur", header: "Current $/mo", cell: (w) => fmtUsd(w.currentMonthlyUsd) },
    { key: "rec", header: "Recommended $/mo", cell: (w) => fmtUsd(w.recommendedMonthlyUsd) },
    { key: "sav", header: "Savings $/mo", cell: (w) => <span className="text-aion-ok">{fmtUsd(w.potentialMonthlySavingsUsd)}</span> },
  ];

  const findingColumns: Column<CostFinding & { key: string }>[] = [
    { key: "kind", header: "Kind", cell: (f) => <Badge variant="neutral">{f.kind}</Badge> },
    { key: "sev", header: "Severity", cell: (f) => <Badge variant="severity" severity={f.severity}>{titleCase(f.severity)}</Badge> },
    { key: "subject", header: "Workload", cell: (f) => `${f.namespace ?? "—"}/${f.workloadName ?? "—"}` },
    { key: "msg", header: "Message", cell: (f) => f.message },
    { key: "sav", header: "Savings $/mo", cell: (f) => fmtUsd(f.monthlySavingsUsd) },
  ];

  const recColumns: Column<CostRecommendation & { key: string }>[] = [
    { key: "prio", header: "Priority", cell: (r) => <Badge variant={r.priority === "p0" ? "danger" : r.priority === "p1" ? "warn" : "neutral"}>{r.priority.toUpperCase()}</Badge> },
    { key: "title", header: "Recommendation", cell: (r) => r.title },
    { key: "detail", header: "Detail", cell: (r) => <span className="text-xs text-aion-muted">{r.detail}</span> },
    { key: "sav", header: "Monthly $", cell: (r) => fmtUsd(r.monthlySavingsUsd) },
    { key: "savY", header: "Annual $", cell: (r) => fmtUsd(r.annualSavingsUsd) },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cost Intelligence"
        subtitle="Resource waste, over-provisioning, and cost optimization recommendations."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Cost" }]}
      />

      {a && (
        <KpiGrid>
          <KpiTile label="Current monthly" value={fmtUsd(a.currentMonthlyUsd)} />
          <KpiTile label="Recommended monthly" value={fmtUsd(a.recommendedMonthlyUsd)} />
          <KpiTile label="Potential savings" value={fmtUsd(a.potentialMonthlySavingsUsd)} hint={`${Math.round((a.potentialMonthlySavingsUsd / Math.max(1, a.currentMonthlyUsd)) * 100)}% reduction`} />
          <KpiTile label="Workloads analysed" value={fmtNumber(a.workloads.length)} />
        </KpiGrid>
      )}

      <Card>
        <Card.Header title="Per-workload cost" subtitle="Current vs recommended monthly cost" />
        <Card.Body>
          <DataTable
            rows={workloads.items.map((w) => ({ ...w, key: w.workloadId }))}
            columns={workloadColumns}
            rowKey={(w) => w.workloadId}
          />
        </Card.Body>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <Card.Header title={`Findings (${findings.total})`} />
          <Card.Body>
            <DataTable
              rows={findings.items.map((f) => ({ ...f, key: f.id }))}
              columns={findingColumns}
              rowKey={(f) => f.id}
            />
          </Card.Body>
        </Card>
        <Card>
          <Card.Header title={`Recommendations (${recommendations.total})`} />
          <Card.Body>
            <DataTable
              rows={recommendations.items.map((r) => ({ ...r, key: r.id }))}
              columns={recColumns}
              rowKey={(r) => r.id}
            />
          </Card.Body>
        </Card>
      </div>
    </div>
  );
}
