import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase } from "@/lib/format";
import type { Namespace } from "@/types/infrastructure";

/**
 * Namespace Explorer — list / filter namespaces across all
 * clusters and drill into the per-namespace health view.
 */
export function NamespaceExplorer() {
  const { data: clusters } = useFetch(api.kubernetesClusters, { items: [], total: 0 });
  const [clusterId, setClusterId] = useState<string | undefined>(undefined);
  const { data: namespaces } = useFetch(
    () => api.kubernetesNamespaces(clusterId),
    { items: [], total: 0 },
  );

  const columns: Column<Namespace & { key: string }>[] = [
    { key: "name", header: "Namespace", cell: (n) => <span className="font-medium">{n.name}</span> },
    { key: "clusterName", header: "Cluster", cell: (n) => n.clusterName },
    { key: "workloadCount", header: "Workloads", cell: (n) => fmtNumber(n.workloadCount) },
    { key: "runningPods", header: "Running", cell: (n) => fmtNumber(n.runningPods) },
    { key: "pendingPods", header: "Pending", cell: (n) => fmtNumber(n.pendingPods) },
    { key: "failedPods", header: "Failed", cell: (n) => <span className={n.failedPods > 0 ? "text-severity-high" : ""}>{fmtNumber(n.failedPods)}</span> },
    { key: "restartsLast1h", header: "Restarts 1h", cell: (n) => fmtNumber(n.restartsLast1h) },
    { key: "phase", header: "Phase", cell: (n) => <Badge variant={n.phase === "active" ? "ok" : "warn"}>{titleCase(n.phase)}</Badge> },
  ];

  const totalPods = namespaces.items.reduce((a, n) => a + n.podCount, 0);
  const totalFailed = namespaces.items.reduce((a, n) => a + n.failedPods, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Namespace Explorer"
        subtitle="List and filter namespaces across your clusters."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Namespaces" }]}
        actions={
          <select
            className="rounded-md border border-aion-border bg-aion-surface px-2 py-1 text-sm text-aion-text"
            value={clusterId ?? ""}
            onChange={(e) => setClusterId(e.target.value || undefined)}
          >
            <option value="">All clusters</option>
            {clusters.items.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        }
      />

      <KpiGrid>
        <KpiTile label="Namespaces" value={fmtNumber(namespaces.total)} />
        <KpiTile label="Pods" value={fmtNumber(totalPods)} />
        <KpiTile label="Failed pods" value={fmtNumber(totalFailed)} />
      </KpiGrid>

      <Card>
        <Card.Header title="Namespaces" />
        <Card.Body>
          <DataTable
            rows={namespaces.items.map((n) => ({ ...n, key: n.id }))}
            columns={columns}
            rowKey={(n) => n.id}
          />
        </Card.Body>
      </Card>
    </div>
  );
}
