import clsx from "clsx";
import type { ReactNode } from "react";
import { TrendingDown, TrendingUp, Minus } from "lucide-react";
import type { Kpi as KpiType } from "@/types";

/**
 * KpiTile — single-metric tile for the dashboard top row.
 *
 * Two shapes are supported:
 *   - `{ kpi: Kpi }`     — the original API-driven shape
 *   - `{ label, value, hint }` — the inline / hand-composed
 *     shape used by the Sprint 4 infrastructure modules
 */
export function KpiTile(props: { kpi: KpiType } | { label: string; value: ReactNode; hint?: string }) {
  let label: ReactNode;
  let value: ReactNode;
  let hint: ReactNode;
  let trend: "up" | "down" | "flat" | undefined;
  let delta: number | undefined;
  if ("kpi" in props) {
    label = props.kpi.label;
    value = props.kpi.value;
    hint = props.kpi.hint;
    trend = props.kpi.trend;
    delta = props.kpi.delta;
  } else {
    label = props.label;
    value = props.value;
    hint = props.hint;
  }
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  const trendColor =
    trend === "up" ? "text-aion-ok" : trend === "down" ? "text-aion-danger" : "text-aion-muted";
  return (
    <div className="aion-card-hover p-4">
      <div className="text-[11px] uppercase tracking-wider text-aion-muted">
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <div className="text-2xl font-semibold text-aion-text">{value}</div>
        {typeof delta === "number" && (
          <span className={clsx("inline-flex items-center gap-0.5 text-xs", trendColor)}>
            <TrendIcon className="h-3 w-3" />
            {Math.abs(delta)}%
          </span>
        )}
      </div>
      {hint && <div className="mt-1 text-[11px] text-aion-muted">{hint}</div>}
    </div>
  );
}

export function KpiGrid({ children }: { children: ReactNode }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      {children}
    </div>
  );
}
