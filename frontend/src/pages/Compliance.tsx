import { ClipboardCheck, FileText } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel, titleCase } from "@/lib/format";
import type { ComplianceControl } from "@/types";

const statusColor: Record<ComplianceControl["status"], string> = {
  pass: "#22c55e",
  partial: "#f59e0b",
  fail: "#ef4444",
  "not-assessed": "#94a3b8",
};

const columns: Column<ComplianceControl>[] = [
  {
    key: "control",
    header: "Control",
    cell: (c) => (
      <div>
        <div className="aion-mono text-[11px] text-aion-muted">
          {c.framework} · {c.id}
        </div>
        <div className="font-medium text-aion-text">{c.title}</div>
        <div className="aion-mono text-[11px]">{c.family}</div>
      </div>
    ),
  },
  {
    key: "status",
    header: "Status",
    cell: (c) => (
      <Badge
        variant={
          c.status === "pass"
            ? "ok"
            : c.status === "partial"
              ? "warn"
              : c.status === "fail"
                ? "danger"
                : "neutral"
        }
      >
        {titleCase(c.status)}
      </Badge>
    ),
  },
  {
    key: "evidence",
    header: "Evidence",
    cell: (c) => <span className="aion-mono">{c.evidenceCount} items</span>,
  },
  {
    key: "assessed",
    header: "Last assessed",
    cell: (c) => <span className="aion-mono">{fmtRel(c.lastAssessedAt)}</span>,
  },
  {
    key: "actions",
    header: "",
    className: "text-right",
    cell: () => (
      <Button size="sm" variant="ghost">
        <FileText className="h-3.5 w-3.5" /> View
      </Button>
    ),
  },
];

export function CompliancePage() {
  const { data } = useFetch(api.compliance, []);

  const counts = (data ?? []).reduce<Record<string, number>>(
    (acc, c) => ({ ...acc, [c.status]: (acc[c.status] ?? 0) + 1 }),
    {}
  );
  const chartData = [
    { status: "pass", count: counts.pass ?? 0 },
    { status: "partial", count: counts.partial ?? 0 },
    { status: "fail", count: counts.fail ?? 0 },
    { status: "not-assessed", count: counts["not-assessed"] ?? 0 },
  ];

  return (
    <div>
      <PageHeader
        title="Compliance"
        subtitle="CIS Controls v8 and NIST 800-53 posture, with automated evidence collection."
        breadcrumbs={[{ label: "AionUi" }, { label: "Compliance" }]}
        actions={
          <Button size="sm" variant="primary">
            <ClipboardCheck className="h-3.5 w-3.5" /> Run assessment
          </Button>
        }
      />

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <Card.Header
            title="Control status distribution"
            subtitle="Across all enabled frameworks"
          />
          <Card.Body>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2742" />
                  <XAxis dataKey="status" stroke="#8a93a6" fontSize={11} />
                  <YAxis stroke="#8a93a6" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "#11172b",
                      border: "1px solid #1f2742",
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {chartData.map((d) => (
                      <Cell key={d.status} fill={statusColor[d.status]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card.Body>
        </Card>

        <Card>
          <Card.Header title="Frameworks" />
          <Card.Body className="space-y-2 text-sm">
            {[
              { name: "CIS Controls v8", score: "92%", state: "ok" as const },
              { name: "NIST 800-53 r5", score: "78%", state: "warn" as const },
              { name: "SOC 2 Type II", score: "—", state: "info" as const },
              { name: "ISO 27001:2022", score: "—", state: "info" as const },
            ].map((f) => (
              <div
                key={f.name}
                className="flex items-center justify-between rounded-md border border-aion-border bg-aion-surface2 px-3 py-2"
              >
                <span className="text-aion-text">{f.name}</span>
                <Badge variant={f.state}>{f.score}</Badge>
              </div>
            ))}
          </Card.Body>
        </Card>
      </div>

      <DataTable
        rows={data ?? []}
        columns={columns}
        rowKey={(c) => c.id}
        empty="No compliance controls configured."
      />
    </div>
  );
}
