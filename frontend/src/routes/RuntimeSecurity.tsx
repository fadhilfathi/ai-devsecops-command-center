import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase } from "@/lib/format";
import type { RuntimeRisk } from "@/types/infrastructure";

/**
 * Runtime Security — risk findings, categories, and rollup report.
 */
export function RuntimeSecurity() {
  const { data: risksData } = useFetch(api.runtimeRisks, { items: [], total: 0 });
  const { data: reportData } = useFetch(api.runtimeReport, { items: [], total: 0 });
  const report = reportData.items[0];
  const [filter, setFilter] = useState<"all" | RuntimeRisk["level"]>("all");

  const filtered = filter === "all" ? risksData.items : risksData.items.filter((r) => r.level === filter);

  const columns: Column<RuntimeRisk & { key: string }>[] = [
    {
      key: "rule", header: "Rule", cell: (r) => (
        <div>
          <div className="font-medium">{r.ruleName}</div>
          <div className="text-[11px] text-aion-muted">{r.ruleId} · {r.category}</div>
        </div>
      ),
    },
    { key: "subject", header: "Subject", cell: (r) => `${r.namespace}/${r.subjectName}` },
    {
      key: "level", header: "Level", cell: (r) => (
        <Badge variant="severity" severity={r.level === "critical" ? "critical" : r.level === "high" ? "high" : r.level === "medium" ? "medium" : "low"}>
          {titleCase(r.level)}
        </Badge>
      ),
    },
    { key: "message", header: "Message", cell: (r) => <span className="text-xs">{r.message}</span> },
    {
      key: "remediation", header: "Remediation", cell: (r) => <span className="text-xs text-aion-muted">{r.remediation}</span>,
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Runtime Security"
        subtitle="Kubernetes runtime-risk findings and rollup report."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Runtime Security" }]}
        actions={
          <select
            className="rounded-md border border-aion-border bg-aion-surface px-2 py-1 text-sm text-aion-text"
            value={filter}
            onChange={(e) => setFilter(e.target.value as typeof filter)}
          >
            <option value="all">All levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        }
      />

      {report && (
        <KpiGrid>
          <KpiTile label="Risk level" value={titleCase(report.riskLevel)} />
          <KpiTile label="Score" value={`${report.score}/100`} />
          <KpiTile label="Critical" value={fmtNumber(report.counts.critical)} />
          <KpiTile label="High" value={fmtNumber(report.counts.high)} />
          <KpiTile label="Medium" value={fmtNumber(report.counts.medium)} />
          <KpiTile label="Low" value={fmtNumber(report.counts.low)} />
        </KpiGrid>
      )}

      <Card>
        <Card.Header title={`Findings (${filtered.length})`} />
        <Card.Body>
          <DataTable
            rows={filtered.map((r) => ({ ...r, key: r.id }))}
            columns={columns}
            rowKey={(r) => r.id}
          />
        </Card.Body>
      </Card>

      {report && report.recommendations.length > 0 && (
        <Card>
          <Card.Header title="Top recommendations" subtitle="One per rule, ranked by level" />
          <Card.Body>
            <ul className="space-y-2">
              {report.recommendations.map((rec) => (
                <li key={rec.id} className="rounded-md border border-aion-border p-3">
                  <div className="flex items-center gap-2">
                    <Badge variant="severity" severity={rec.level === "critical" ? "critical" : rec.level === "high" ? "high" : "medium"}>
                      {titleCase(rec.level)}
                    </Badge>
                    <span className="text-sm font-medium">{rec.title}</span>
                    <span className="text-[11px] text-aion-muted">({fmtNumber(rec.affectedCount)} affected)</span>
                  </div>
                  <p className="mt-1 text-xs text-aion-muted">{rec.detail}</p>
                </li>
              ))}
            </ul>
          </Card.Body>
        </Card>
      )}
    </div>
  );
}
