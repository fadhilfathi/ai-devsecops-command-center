import { useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import type { Severity, VulnTimelineRange } from "@/types";

const RANGES: { id: VulnTimelineRange; label: string }[] = [
  { id: "7d",  label: "7d" },
  { id: "30d", label: "30d" },
  { id: "90d", label: "90d" },
  { id: "1y",  label: "1y" },
];

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "hsl(0 84% 60%)",
  high:     "hsl(20 90% 55%)",
  medium:   "hsl(38 92% 50%)",
  low:      "hsl(199 89% 60%)",
  info:     "hsl(215 14% 60%)",
};

/**
 * VulnTimeline — stacked area chart of new vulnerabilities per day,
 * split by severity. Date range selector (7d / 30d / 90d / 1y).
 *
 * Sprint 2 / S2.6 visualization #2. Consumes
 * `GET /api/security/vuln-timeline?range={range}` (S2.5).
 *
 * Accessibility: the chart has an accessible <table> fallback below it
 * that screen-reader users can navigate. Keyboard users can pick the
 * range with the tab-cycle button group.
 */
export function VulnTimeline() {
  const [range, setRange] = useState<VulnTimelineRange>("30d");
  const { data, loading } = useFetch(() => api.vulnTimeline(range), [range]);

  return (
    <Card>
      <Card.Header
        title="Vulnerability Timeline"
        subtitle="New vulnerabilities per period, stacked by severity"
        actions={
          <div
            role="group"
            aria-label="Date range"
            className="inline-flex rounded-md border border-border bg-surface-2 p-0.5"
          >
            {RANGES.map((r) => (
              <button
                key={r.id}
                type="button"
                onClick={() => setRange(r.id)}
                aria-pressed={range === r.id}
                className={`rounded px-2 py-1 text-[11px] font-medium transition-colors ${
                  range === r.id
                    ? "bg-accent/15 text-accent"
                    : "text-muted hover:text-text"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
        }
      />
      <Card.Body>
        {loading || !data ? (
          <div className="grid h-64 place-items-center text-sm text-muted">
            Loading timeline…
          </div>
        ) : data.length === 0 ? (
          <div className="grid h-64 place-items-center text-sm text-muted">
            No data for this range.
          </div>
        ) : (
          <>
            <div
              className="h-64"
              role="img"
              aria-label={`Vulnerability timeline, last ${range}, stacked by severity`}
            >
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={data}
                  margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
                >
                  <defs>
                    {SEVERITY_ORDER.map((s) => (
                      <linearGradient
                        key={s}
                        id={`grad-${s}`}
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor={SEVERITY_COLORS[s]}
                          stopOpacity={0.6}
                        />
                        <stop
                          offset="100%"
                          stopColor={SEVERITY_COLORS[s]}
                          stopOpacity={0.1}
                        />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis
                    dataKey="date"
                    stroke="hsl(var(--muted))"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    stroke="hsl(var(--muted))"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "hsl(var(--surface))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                    labelStyle={{ color: "hsl(var(--text))" }}
                  />
                  <Legend
                    wrapperStyle={{ fontSize: 11 }}
                    iconType="circle"
                    iconSize={8}
                  />
                  {SEVERITY_ORDER.map((s) => (
                    <Area
                      key={s}
                      type="monotone"
                      dataKey={s}
                      stackId="1"
                      stroke={SEVERITY_COLORS[s]}
                      fill={`url(#grad-${s})`}
                      strokeWidth={1.5}
                    />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Accessible data-table fallback. */}
            <details className="mt-3">
              <summary className="cursor-pointer text-[11px] text-muted hover:text-text">
                View as data table
              </summary>
              <div className="mt-2 max-h-64 overflow-auto">
                <table className="w-full aion-mono text-[11px]">
                  <thead className="sticky top-0 bg-surface-2">
                    <tr>
                      <th className="px-2 py-1 text-left">Date</th>
                      {SEVERITY_ORDER.map((s) => (
                        <th key={s} className="px-2 py-1 text-right">
                          {s}
                        </th>
                      ))}
                      <th className="px-2 py-1 text-right">total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.map((p) => {
                      const total = SEVERITY_ORDER.reduce(
                        (acc, s) => acc + (p[s] as number),
                        0
                      );
                      return (
                        <tr key={p.date} className="border-t border-border/60">
                          <td className="px-2 py-1">{p.date}</td>
                          {SEVERITY_ORDER.map((s) => (
                            <td key={s} className="px-2 py-1 text-right">
                              {p[s]}
                            </td>
                          ))}
                          <td className="px-2 py-1 text-right font-semibold">
                            {total}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </details>
          </>
        )}
      </Card.Body>
    </Card>
  );
}
