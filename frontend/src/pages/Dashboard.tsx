import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, ArrowRight, ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel, severityClasses, titleCase } from "@/lib/format";

const POSTURE_SERIES = [
  { day: "Mon", score: 86 },
  { day: "Tue", score: 88 },
  { day: "Wed", score: 87 },
  { day: "Thu", score: 90 },
  { day: "Fri", score: 91 },
  { day: "Sat", score: 92 },
  { day: "Sun", score: 92 },
];

export function DashboardPage() {
  const { data: kpis } = useFetch(api.dashboardKpis, []);
  const { data: events } = useFetch(api.eventStream, []);

  return (
    <div>
      <PageHeader
        title="Security Posture"
        subtitle="Live view across the estate. Auto-refresh every 30s."
        breadcrumbs={[{ label: "AionUi" }, { label: "Dashboard" }]}
        actions={
          <>
            <Button size="sm" variant="secondary">
              Export report
            </Button>
            <Button size="sm" variant="primary">
              Run scan
            </Button>
          </>
        }
      />

      {/* KPI row */}
      <section aria-label="Key metrics" className="mb-6">
        <KpiGrid>
          {(kpis ?? []).map((k) => (
            <KpiTile key={k.label} kpi={k} />
          ))}
        </KpiGrid>
      </section>

      {/* Posture chart + posture summary */}
      <section className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <Card.Header
            title="Compliance posture (7d)"
            subtitle="Weighted average across CISv8, NIST 800-53"
            actions={
              <Badge variant="ok">
                <ShieldCheck className="h-3 w-3" /> healthy
              </Badge>
            }
          />
          <Card.Body>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={POSTURE_SERIES} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="postureFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#5eead4" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#5eead4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2742" />
                  <XAxis dataKey="day" stroke="#8a93a6" fontSize={11} />
                  <YAxis stroke="#8a93a6" fontSize={11} domain={[60, 100]} />
                  <Tooltip
                    contentStyle={{
                      background: "#11172b",
                      border: "1px solid #1f2742",
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                    labelStyle={{ color: "#e6ebf5" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="#5eead4"
                    strokeWidth={2}
                    fill="url(#postureFill)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card.Body>
        </Card>

        <Card>
          <Card.Header
            title="Top actions"
            subtitle="Auto-remediation candidates"
            actions={
              <Badge variant="info">
                <Activity className="h-3 w-3" /> 12 pending
              </Badge>
            }
          />
          <Card.Body className="space-y-3">
            {[
              { sev: "critical" as const, msg: "Bump xz-utils to 5.6.1 in 4 services" },
              { sev: "high" as const, msg: "Rotate GitHub PAT exposed in CI logs" },
              { sev: "medium" as const, msg: "Rebase 6 PRs onto debian:bookworm" },
              { sev: "low" as const, msg: "Tighten S3 bucket policy on artifacts-prod" },
            ].map((a, i) => (
              <div
                key={i}
                className="flex items-start gap-3 rounded-md border border-aion-border bg-aion-surface2 p-3"
              >
                <Badge severity={a.sev}>{titleCase(a.sev)}</Badge>
                <div className="flex-1 text-sm text-aion-text">{a.msg}</div>
                <Button size="sm" variant="ghost">
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </Card.Body>
        </Card>
      </section>

      {/* Event stream */}
      <section className="mb-6">
        <Card>
          <Card.Header
            title="Live event stream"
            subtitle="From agent-core, GitHub, SIEM, and integrations"
            actions={
              <Button size="sm" variant="ghost">
                Open in Events
              </Button>
            }
          />
          <Card.Body className="p-0">
            <ul className="divide-y divide-aion-border">
              {(events ?? []).map((e) => (
                <li
                  key={e.id}
                  className="grid grid-cols-[110px_90px_1fr] items-center gap-3 px-4 py-2.5 text-sm hover:bg-aion-surface2"
                >
                  <span className="aion-mono">{fmtRel(e.ts)}</span>
                  <span
                    className={`inline-flex w-fit items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityClasses(
                      e.level
                    )}`}
                  >
                    {titleCase(e.level)}
                  </span>
                  <span className="truncate text-aion-text">
                    <span className="aion-mono mr-2">[{e.source}]</span>
                    {e.message}
                  </span>
                </li>
              ))}
            </ul>
          </Card.Body>
        </Card>
      </section>
    </div>
  );
}
