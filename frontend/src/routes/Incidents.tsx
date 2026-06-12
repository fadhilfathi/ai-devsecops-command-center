import { ShieldAlert, Plus } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtDate, titleCase } from "@/lib/format";
import type { Incident } from "@/types";

const columns: Column<Incident>[] = [
  {
    key: "id",
    header: "Incident",
    cell: (i) => (
      <div>
        <div className="font-medium text-aion-text">{i.id}</div>
        <div className="text-xs text-aion-muted">{i.title}</div>
      </div>
    ),
  },
  {
    key: "sev",
    header: "Severity",
    cell: (i) => <Badge severity={i.severity}>{titleCase(i.severity)}</Badge>,
  },
  {
    key: "status",
    header: "Status",
    cell: (i) => (
      <Badge
        variant={
          i.status === "resolved"
            ? "ok"
            : i.status === "open" || i.status === "investigating"
              ? "danger"
              : "warn"
        }
      >
        {titleCase(i.status)}
      </Badge>
    ),
  },
  {
    key: "source",
    header: "Source",
    cell: (i) => <span className="aion-mono">{i.source}</span>,
  },
  {
    key: "assignee",
    header: "Assignee",
    cell: (i) => <span className="aion-mono">{i.assignee}</span>,
  },
  {
    key: "created",
    header: "Created",
    cell: (i) => <span className="aion-mono">{fmtDate(i.createdAt)}</span>,
  },
  {
    key: "updated",
    header: "Updated",
    cell: (i) => <span className="aion-mono">{fmtDate(i.updatedAt)}</span>,
  },
];

export function IncidentsPage() {
  const { data } = useFetch(api.incidents, []);

  return (
    <div>
      <PageHeader
        title="Incidents"
        subtitle="Active and historical security incidents. Triage, investigate, and resolve from here."
        breadcrumbs={[{ label: "AionUi" }, { label: "Incidents" }]}
        actions={
          <Button size="sm" variant="primary">
            <Plus className="h-3.5 w-3.5" /> Declare incident
          </Button>
        }
      />

      {/* Active incidents callout */}
      {(data ?? []).filter((i) => i.status !== "resolved").length > 0 && (
        <Card className="mb-4 border-severity-critical/40">
          <Card.Header
            title={
              <span className="inline-flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-severity-critical" />
                Active incidents requiring attention
              </span>
            }
            actions={
              <Badge variant="danger">
                {(data ?? []).filter((i) => i.status !== "resolved").length} active
              </Badge>
            }
          />
          <Card.Body className="space-y-3">
            {(data ?? [])
              .filter((i) => i.status !== "resolved")
              .map((i) => (
                <div
                  key={i.id}
                  className="flex items-start gap-3 rounded-md border border-aion-border bg-aion-surface2 p-3"
                >
                  <Badge severity={i.severity}>{titleCase(i.severity)}</Badge>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-aion-text">{i.title}</div>
                    <div className="mt-0.5 text-xs text-aion-muted">{i.summary}</div>
                  </div>
                  <Button size="sm" variant="secondary">
                    Open
                  </Button>
                </div>
              ))}
          </Card.Body>
        </Card>
      )}

      <DataTable
        rows={data ?? []}
        columns={columns}
        rowKey={(i) => i.id}
        empty="No incidents recorded yet."
      />
    </div>
  );
}
