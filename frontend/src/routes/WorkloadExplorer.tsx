import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase, fmtCpu, fmtBytes } from "@/lib/format";
import type { Workload } from "@/types/infrastructure";

/**
 * Workload Explorer — list / filter workloads (any kind) by
 * cluster, namespace, or health.
 */
export function WorkloadExplorer() {
  const { data: clusters } = useFetch(api.kubernetesClusters, { items: [], total: 0 });
  const [clusterId, setClusterId] = useState<string | undefined>(undefined);
  const [namespace, setNamespace] = useState<string | undefined>(undefined);
  const { data: workloads } = useFetch(
    () => api.kubernetesWorkloads(clusterId, namespace),
    { items: [], total: 0 },
  );

  const columns: Column<Workload & { key: string }>[] = [
    { key: "name", header: "Workload", cell: (w) => (
      <div>
        <div className="font-medium">{w.name}</div>
        <div className="text-[11px] text-aion-muted">{w.image ?? "—"}</div>
      </div>
    ) },
    { key: "kind", header: "Kind", cell: (w) => <Badge variant="neutral">{w.kind}</Badge> },
    { key: "namespace", header: "Namespace", cell: (w) => w.namespace },
    { key: "replicas", header: "Replicas", cell: (w) => `${w.replicas.ready}/${w.replicas.desired}` },
    { key: "health", header: "Health", cell: (w) => (
      <Badge variant={
        w.health === "healthy" ? "ok"
        : w.health === "degraded" ? "warn"
        : w.health === "unhealthy" ? "danger"
        : "neutral"
      }>{titleCase(w.health)}</Badge>
    ) },
    { key: "cpu", header: "CPU req/lim", cell: (w) => `${fmtCpu(w.resources.cpuRequestsMillicores)} / ${fmtCpu(w.resources.cpuLimitsMillicores)}` },
    { key: "mem", header: "Memory req/lim", cell: (w) => `${fmtBytes(w.resources.memoryRequestsBytes)} / ${fmtBytes(w.resources.memoryLimitsBytes)}` },
  ];

  const healthy = workloads.items.filter((w) => w.health === "healthy").length;
  const unhealthy = workloads.items.filter((w) => w.health === "unhealthy" || w.health === "degraded").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Workload Explorer"
        subtitle="List and filter workloads across your clusters and namespaces."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Workloads" }]}
        actions={
          <div className="flex gap-2">
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
            <input
              type="text"
              placeholder="namespace…"
              className="rounded-md border border-aion-border bg-aion-surface px-2 py-1 text-sm text-aion-text"
              value={namespace ?? ""}
              onChange={(e) => setNamespace(e.target.value || undefined)}
            />
          </div>
        }
      />

      <KpiGrid>
        <KpiTile label="Workloads" value={fmtNumber(workloads.total)} />
        <KpiTile label="Healthy" value={fmtNumber(healthy)} />
        <KpiTile label="Degraded / Unhealthy" value={fmtNumber(unhealthy)} />
      </KpiGrid>

      <Card>
        <Card.Header title="Workloads" />
        <Card.Body>
          <DataTable
            rows={workloads.items.map((w) => ({ ...w, key: w.id }))}
            columns={columns}
            rowKey={(w) => w.id}
          />
        </Card.Body>
      </Card>
    </div>
  );
}
