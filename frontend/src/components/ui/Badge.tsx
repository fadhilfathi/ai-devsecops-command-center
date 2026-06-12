import clsx from "clsx";
import type { ReactNode } from "react";
import { severityClasses, titleCase } from "@/lib/format";
import type { Severity } from "@/types";

/**
 * Badge — small inline status / severity indicator.
 *
 * Variants:
 *   - "severity"  → color-coded by Severity token (critical/high/...)
 *   - "neutral"   → default subtle badge
 *   - "ok" | "warn" | "danger" | "info" → explicit semantic colors
 */
type Variant = "severity" | "neutral" | "ok" | "warn" | "danger" | "info";

const variantClasses: Record<Variant, string> = {
  severity: "border", // set per severity in the component body
  neutral: "bg-aion-surface2 text-aion-muted border border-aion-border",
  ok: "bg-aion-ok/15 text-aion-ok border border-aion-ok/30",
  warn: "bg-aion-warn/15 text-aion-warn border border-aion-warn/30",
  danger: "bg-aion-danger/15 text-aion-danger border border-aion-danger/30",
  info: "bg-aion-info/15 text-aion-info border border-aion-info/30",
};

export function Badge({
  children,
  variant = "neutral",
  severity,
  className,
}: {
  children: ReactNode;
  variant?: Variant;
  severity?: Severity;
  className?: string;
}) {
  const classes =
    variant === "severity" && severity
      ? severityClasses(severity)
      : variantClasses[variant];

  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        classes,
        className
      )}
    >
      {children ?? (severity ? titleCase(severity) : null)}
    </span>
  );
}
