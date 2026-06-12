import clsx from "clsx";
import type { ReactNode } from "react";
import { TrendingDown, TrendingUp, Minus } from "lucide-react";
import type { Kpi as KpiType } from "@/types";

/**
 * KpiTile — single-metric tile for the dashboard top row.
 *
 * Pass either a `Kpi` object from the API or compose by hand.
 */
export function KpiTile({ kpi }: { kpi: KpiType }) {
  const TrendIcon =
    kpi.trend === "up"
      ? TrendingUp
      : kpi.trend === "down"
        ? TrendingDown
        : Minus;
  const trendColor =
    kpi.trend === "up"
      ? "text-aion-ok"
      : kpi.trend === "down"
        ? "text-aion-danger"
        : "text-aion-muted";

  return (
    <div className="aion-card-hover p-4">
      <div className="text-[11px] uppercase tracking-wider text-aion-muted">
        {kpi.label}
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <div className="text-2xl font-semibold text-aion-text">{kpi.value}</div>
        {typeof kpi.delta === "number" && (
          <span className={clsx("inline-flex items-center gap-0.5 text-xs", trendColor)}>
            <TrendIcon className="h-3 w-3" />
            {Math.abs(kpi.delta)}%
          </span>
        )}
      </div>
      {kpi.hint && <div className="mt-1 text-[11px] text-aion-muted">{kpi.hint}</div>}
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
