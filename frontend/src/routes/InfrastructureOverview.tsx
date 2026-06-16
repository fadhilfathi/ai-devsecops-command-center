import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { Button } from "@/components/ui/Button";
import { Server, Boxes, GitBranch, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase } from "@/lib/format";

/**
 * Infrastructure Overview — top-level rollup across the
 * tenant's clusters, namespaces, workloads, runtime risks,
 * and cost intelligence.
 */
export function InfrastructureOverview() {
  const { data: clusters } = useFetch(api.kubernetesClusters, { items: [], total: 0 });
  const { data: namespaces } = useFetch(api.kubernetesNamespaces, { items: [], total: 0 });
  const { data: workloads } = useFetch(() => api.kubernetesWorkloads(), { items: [], total: 0 });
  const { data: runtimeReport } = useFetch(api.runtimeReport, { items: [], total: 0 });
  const { data: cost } = useFetch(api.costAnalysis, { items: [], total: 0 });
  const { data: health } = useFetch(api.healthClusters, { items: [], total: 0 });
  const [showAll, setShowAll] = useState(true);

  const report = runtimeReport.items[0];
  const costItem = cost.items[0];
  const healthItem = health.items[0];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Infrastructure Overview"
        subtitle="Rollup of clusters, workloads, runtime risk, and cost across your fleet."
        breadcrumbs={[{ label: "AionUi" }, { label: "Infrastructure" }]}
        actions={
          <Button size="sm" variant="primary" onClick={() => setShowAll((v) => !v)}>
            {showAll ? "Hide" : "Show"} cluster details
          </Button>
        }
      />

      <KpiGrid>
        <KpiTile
          label="Clusters"
          value={fmtNumber(clusters.total)}
          hint={`${clusters.items.filter((c) => c.environment === "prod").length} prod`}
        />
        <KpiTile
          label="Namespaces"
          value={fmtNumber(namespaces.total)}
          hint={`${namespaces.items.reduce((a, n) => a + n.workloadCount, 0)} workloads`}
        />
        <KpiTile
          label="Workloads"
          value={fmtNumber(workloads.total)}
          hint={`${workloads.items.filter((w) => w.health === "healthy").length} healthy`}
        />
        <KpiTile
          label="Runtime risk"
          value={report ? titleCase(report.riskLevel) : "—"}
          hint={report ? `score ${report.score}/100` : "—"}
        />
        <KpiTile
          label="Monthly cost"
          value={costItem ? `$${fmtNumber(Math.round(costItem.currentMonthlyUsd))}` : "—"}
          hint={costItem ? `save $${fmtNumber(Math.round(costItem.potentialMonthlySavingsUsd))}/mo` : "—"}
        />
        <KpiTile
          label="Cluster health"
          value={healthItem ? `${healthItem.score.score} (${healthItem.score.band})` : "—"}
          hint={healthItem ? titleCase(healthItem.score.status) : "—"}
        />
      </KpiGrid>

      <section aria-label="Cluster list" className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {clusters.items.map((c) => (
          <Card key={c.id}>
            <Card.Header
              title={c.name}
              subtitle={`${c.provider} · ${c.k8sVersion ?? "?"} · ${c.region ?? "—"}`}
              actions={<Badge variant="severity" severity={c.phase === "active" ? "info" : "warn"}>{titleCase(c.phase)}</Badge>}
            />
            <Card.Body>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <Stat icon={<Server className="h-4 w-4" />} label="Nodes" value={`${c.readyNodes}/${c.nodeCount}`} />
                <Stat icon={<Boxes className="h-4 w-4" />} label="CPU" value={`${c.totalCpuCores} cores`} />
                <Stat icon={<GitBranch className="h-4 w-4" />} label="Memory" value={`${Math.round(c.totalMemoryBytes / (1024 ** 3))} GiB`} />
                <Stat icon={<AlertTriangle className="h-4 w-4" />} label="Env" value={titleCase(c.environment)} />
              </div>
            </Card.Body>
          </Card>
        ))}
      </section>

      {showAll && (
        <section aria-label="Cost summary" className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <Card.Header title="Cost" subtitle="Last 30d" />
            <Card.Body>
              {costItem ? (
                <div className="grid grid-cols-3 gap-4">
                  <KpiTile label="Current" value={`$${fmtNumber(Math.round(costItem.currentMonthlyUsd))}`} />
                  <KpiTile label="Recommended" value={`$${fmtNumber(Math.round(costItem.recommendedMonthlyUsd))}`} />
                  <KpiTile label="Savings" value={`$${fmtNumber(Math.round(costItem.potentialMonthlySavingsUsd))}`} />
                </div>
              ) : (
                <div className="text-sm text-aion-muted">No cost data available.</div>
              )}
            </Card.Body>
          </Card>
          <Card>
            <Card.Header title="Runtime security" subtitle="Last 24h" />
            <Card.Body>
              {report ? (
                <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
                  <KpiTile label="Risk" value={titleCase(report.riskLevel)} />
                  <KpiTile label="Score" value={`${report.score}/100`} />
                  <KpiTile label="Critical" value={fmtNumber(report.counts.critical)} />
                  <KpiTile label="High" value={fmtNumber(report.counts.high)} />
                </div>
              ) : (
                <div className="text-sm text-aion-muted">No runtime security data available.</div>
              )}
            </Card.Body>
          </Card>
        </section>
      )}
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 text-aion-text">
      <span className="text-aion-muted">{icon}</span>
      <div>
        <div className="text-[10px] uppercase tracking-wide text-aion-muted">{label}</div>
        <div className="text-sm font-medium">{value}</div>
      </div>
    </div>
  );
}
