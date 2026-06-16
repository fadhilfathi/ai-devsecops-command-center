import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase, fmtRel } from "@/lib/format";
import type { Incident } from "@/types";

/**
 * Infrastructure Incidents — incidents correlated to infra events
 * (k8s, runtime, cost, topology). Backed by the same incidents
 * store; the correlation engine in the incident service
 * produces the per-event chains that surface here.
 */
export function InfrastructureIncidents() {
  const { data: incidents } = useFetch(api.incidents, [] as Incident[]);
  const [filter, setFilter] = useState<"all" | Incident["severity"]>("all");

  const filtered = filter === "all" ? incidents : incidents.filter((i) => i.severity === filter);

  const columns: Column<Incident & { key: string }>[] = [
    {
      key: "title", header: "Incident", cell: (i) => (
        <div>
          <div className="font-medium">{i.title}</div>
          <div className="text-[11px] text-aion-muted">{i.summary}</div>
        </div>
      ),
    },
    { key: "sev", header: "Severity", cell: (i) => <Badge variant="severity" severity={i.severity}>{titleCase(i.severity)}</Badge> },
    { key: "status", header: "Status", cell: (i) => <Badge variant={i.status === "resolved" ? "ok" : i.status === "investigating" ? "warn" : "info"}>{titleCase(i.status)}</Badge> },
    { key: "source", header: "Source", cell: (i) => i.source },
    { key: "assignee", header: "Assignee", cell: (i) => i.assignee },
    { key: "updated", header: "Updated", cell: (i) => fmtRel(i.updatedAt) },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Infrastructure Incidents"
        subtitle="Incidents correlated to Kubernetes, runtime, and infrastructure events."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Incidents" }]}
        actions={
          <select
            className="rounded-md border border-aion-border bg-aion-surface px-2 py-1 text-sm text-aion-text"
            value={filter}
            onChange={(e) => setFilter(e.target.value as typeof filter)}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        }
      />

      <KpiGrid>
        <KpiTile label="Total" value={fmtNumber(incidents.length)} />
        <KpiTile label="Critical" value={fmtNumber(incidents.filter((i) => i.severity === "critical").length)} />
        <KpiTile label="Open" value={fmtNumber(incidents.filter((i) => i.status === "open" || i.status === "investigating").length)} />
        <KpiTile label="Resolved" value={fmtNumber(incidents.filter((i) => i.status === "resolved").length)} />
      </KpiGrid>

      <Card>
        <Card.Header title={`Incidents (${filtered.length})`} />
        <Card.Body>
          <DataTable
            rows={filtered.map((i) => ({ ...i, key: i.id }))}
            columns={columns}
            rowKey={(i) => i.id}
          />
        </Card.Body>
      </Card>
    </div>
  );
}
