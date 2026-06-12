import clsx from "clsx";
import { TrendingDown, TrendingUp, Minus } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Sparkline } from "./Sparkline";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel } from "@/lib/format";
import type { SecurityScore, SecurityScoreSubMetric } from "@/types";

const BAND_COLORS: Record<SecurityScore["band"], string> = {
  A: "hsl(var(--success))",
  B: "hsl(var(--info))",
  C: "hsl(var(--warning))",
  D: "hsl(var(--warning))",
  F: "hsl(var(--danger))",
};

const BAND_VARIANT: Record<SecurityScore["band"], "ok" | "info" | "warn" | "danger"> = {
  A: "ok",
  B: "info",
  C: "warn",
  D: "warn",
  F: "danger",
};

/**
 * SecurityScore — composite security score + 5 sub-metric tiles.
 *
 * Sprint 2 / S2.6 visualization #5. Sits at the top of /dashboard.
 * Consumes `GET /api/security/score` (S2.5 contract).
 */
export function SecurityScore() {
  const { data, loading } = useFetch(api.securityScore, []);

  if (loading || !data) {
    return (
      <div
        className="grid grid-cols-1 gap-4 lg:grid-cols-[300px_1fr]"
        aria-busy="true"
        aria-label="Loading security score"
      >
        <Card><Card.Body><div className="h-40 animate-pulse" /></Card.Body></Card>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="aion-card p-4">
              <div className="h-3 w-24 animate-pulse rounded bg-surface-2" />
              <div className="mt-2 h-7 w-16 animate-pulse rounded bg-surface-2" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div
      className="grid grid-cols-1 gap-4 lg:grid-cols-[300px_1fr]"
      aria-label="Security score overview"
    >
      {/* Composite score */}
      <Card>
        <Card.Header
          title="Security Score"
          subtitle="Composite across 5 sub-metrics"
        />
        <Card.Body className="flex flex-col items-center justify-center text-center">
          <div
            className="text-7xl font-bold leading-none tabular-nums"
            style={{ color: BAND_COLORS[data.band] }}
            aria-label={`Composite security score: ${data.composite} out of 100, band ${data.band}`}
          >
            {data.composite}
          </div>
          <div className="aion-mono mt-1 text-[11px] uppercase tracking-wider">
            out of 100
          </div>
          <Badge variant={BAND_VARIANT[data.band]} className="mt-3">
            Band {data.band}
          </Badge>
          <div className="aion-mono mt-3 text-[10px] text-muted">
            generated {fmtRel(data.generatedAt)}
          </div>
        </Card.Body>
      </Card>

      {/* Sub-metrics */}
      <div
        className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3"
        role="list"
      >
        {data.subMetrics.map((m) => (
          <SubMetricTile key={m.id} metric={m} />
        ))}
      </div>
    </div>
  );
}

function SubMetricTile({ metric }: { metric: SecurityScoreSubMetric }) {
  const formatted = formatValue(metric);
  // Invert delta color when "lower is better" (e.g. MTTR, vulns, KEV).
  const inverted = metric.betterWhen === "lower";
  const isImproving =
    typeof metric.delta === "number" &&
    (inverted ? metric.delta < 0 : metric.delta > 0);
  const TrendIcon =
    metric.delta == null
      ? Minus
      : isImproving
        ? TrendingDown // lower is better → down arrow = good
        : TrendingUp;
  const trendColor =
    metric.delta == null
      ? "text-muted"
      : isImproving
        ? "text-success"
        : "text-danger";

  return (
    <div
      role="listitem"
      className="aion-card-hover p-4"
      aria-label={`${metric.label}: ${formatted}`}
    >
      <div className="text-[11px] uppercase tracking-wider text-muted">
        {metric.label}
      </div>
      <div className="mt-1 flex items-baseline justify-between gap-2">
        <div className="text-2xl font-semibold tabular-nums text-text">
          {formatted}
        </div>
        <div className="h-7 w-24 shrink-0">
          <Sparkline
            data={metric.sparkline}
            ariaLabel={`${metric.label} trend`}
          />
        </div>
      </div>
      <div className="mt-1 flex items-center justify-between text-[11px]">
        <span className="text-muted">{metric.hint}</span>
        {typeof metric.delta === "number" && (
          <span
            className={clsx("inline-flex items-center gap-0.5", trendColor)}
            aria-label={`Delta ${isImproving ? "improving" : "worsening"} ${Math.abs(metric.delta)} percent`}
          >
            <TrendIcon className="h-3 w-3" />
            {Math.abs(metric.delta).toFixed(metric.delta % 1 === 0 ? 0 : 1)}%
          </span>
        )}
      </div>
    </div>
  );
}

function formatValue(m: SecurityScoreSubMetric): string {
  switch (m.format) {
    case "percent":
      return `${Math.round(m.value)}%`;
    case "count":
      return new Intl.NumberFormat("en-US").format(Math.round(m.value));
    case "score":
      return m.value.toFixed(1);
    case "duration": {
      // Stored as minutes. Render as "Xh Ym" or "Ym".
      const mins = Math.round(m.value);
      if (mins < 60) return `${mins}m`;
      const h = Math.floor(mins / 60);
      const mm = mins % 60;
      return mm === 0 ? `${h}h` : `${h}h ${mm}m`;
    }
  }
}
