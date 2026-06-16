import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { titleCase, fmtRel } from "@/lib/format";
import type { InfrastructureHealth, HealthIssue, HealthRecommendation } from "@/types/infrastructure";

/**
 * Infrastructure Health — health rollup across the tenant's
 * clusters, with issues and recommendations.
 */
export function InfrastructureHealthPage() {
  const { data: clusters } = useFetch(api.healthClusters, { items: [], total: 0 });
  const { data: namespaces } = useFetch(api.healthNamespaces, { items: [], total: 0 });
  const { data: workloads } = useFetch(api.healthWorkloads, { items: [], total: 0 });
  const { data: pods } = useFetch(api.healthPods, { items: [], total: 0 });
  const { data: issuesData } = useFetch(api.healthIssues, { items: [], total: 0 });
  const { data: recsData } = useFetch(api.healthRecommendations, { items: [], total: 0 });

  const all = [...clusters.items, ...namespaces.items, ...workloads.items, ...pods.items];
  const avg = all.length === 0 ? 0 : Math.round(all.reduce((a, h) => a + h.score.score, 0) / all.length);

  const healthColumns: Column<InfrastructureHealth & { key: string }>[] = [
    { key: "scope", header: "Scope", cell: (h) => <Badge variant="neutral">{h.scope}</Badge> },
    { key: "name", header: "Subject", cell: (h) => h.subject.name },
    { key: "score", header: "Score", cell: (h) => `${h.score.score} (${h.score.band})` },
    { key: "status", header: "Status", cell: (h) => (
      <Badge variant={
        h.score.status === "healthy" ? "ok"
        : h.score.status === "degraded" ? "warn"
        : h.score.status === "unhealthy" ? "danger"
        : "neutral"
      }>{titleCase(h.score.status)}</Badge>
    ) },
    { key: "crit", header: "Crit", cell: (h) => h.score.counts.critical },
    { key: "high", header: "High", cell: (h) => h.score.counts.high },
  ];

  const issueColumns: Column<HealthIssue & { key: string }>[] = [
    { key: "kind", header: "Kind", cell: (i) => <Badge variant="neutral">{i.kind}</Badge> },
    { key: "sev", header: "Severity", cell: (i) => <Badge variant="severity" severity={i.severity}>{titleCase(i.severity)}</Badge> },
    { key: "subj", header: "Subject", cell: (i) => `${i.subject.kind}/${i.subject.name}` },
    { key: "msg", header: "Message", cell: (i) => <span className="text-xs">{i.message}</span> },
    { key: "det", header: "Detected", cell: (i) => fmtRel(i.detectedAt) },
  ];

  const recColumns: Column<HealthRecommendation & { key: string }>[] = [
    { key: "prio", header: "Priority", cell: (r) => (
      <Badge variant={r.priority === "p0" ? "danger" : r.priority === "p1" ? "warn" : "neutral"}>
        {r.priority.toUpperCase()}
      </Badge>
    ) },
    { key: "title", header: "Title", cell: (r) => r.title },
    { key: "action", header: "Action", cell: (r) => <code className="text-[11px] text-aion-muted">{r.action}</code> },
    { key: "affected", header: "Affected", cell: (r) => r.affectedCount },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Infrastructure Health"
        subtitle="Health rollup across clusters, namespaces, workloads, and pods."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Health" }]}
      />

      <KpiGrid>
        <KpiTile label="Average score" value={`${avg}/100`} />
        <KpiTile label="Cluster health" value={clusters.total} />
        <KpiTile label="Workload health" value={workloads.total} />
        <KpiTile label="Open issues" value={issuesData.total} />
        <KpiTile label="Recommendations" value={recsData.total} />
      </KpiGrid>

      <Card>
        <Card.Header title="Per-scope health" />
        <Card.Body>
          <DataTable
            rows={all.map((h) => ({ ...h, key: h.id }))}
            columns={healthColumns}
            rowKey={(h) => h.id}
          />
        </Card.Body>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <Card.Header title={`Issues (${issuesData.total})`} />
          <Card.Body>
            <DataTable
              rows={issuesData.items.map((i) => ({ ...i, key: i.id }))}
              columns={issueColumns}
              rowKey={(i) => i.id}
            />
          </Card.Body>
        </Card>
        <Card>
          <Card.Header title={`Recommendations (${recsData.total})`} />
          <Card.Body>
            <DataTable
              rows={recsData.items.map((r) => ({ ...r, key: r.id }))}
              columns={recColumns}
              rowKey={(r) => r.id}
            />
          </Card.Body>
        </Card>
      </div>
    </div>
  );
}
