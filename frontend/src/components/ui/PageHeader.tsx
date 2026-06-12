import type { ReactNode } from "react";
import clsx from "clsx";

/**
 * PageHeader — the standard title row at the top of every AionUi page.
 * Holds the title, an optional subtitle, breadcrumbs, and a right-side
 * action slot (e.g. "New scan", "Export SBOM").
 */
export function PageHeader({
  title,
  subtitle,
  breadcrumbs,
  actions,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  breadcrumbs?: { label: string; to?: string }[];
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={clsx("mb-6 flex items-start justify-between gap-4", className)}>
      <div className="min-w-0">
        {breadcrumbs && breadcrumbs.length > 0 && (
          <div className="aion-mono mb-1 flex items-center gap-1.5 text-[11px]">
            {breadcrumbs.map((b, i) => (
              <span key={i} className="inline-flex items-center gap-1.5">
                <span className="text-aion-muted">{b.label}</span>
                {i < breadcrumbs.length - 1 && (
                  <span className="text-aion-border">/</span>
                )}
              </span>
            ))}
          </div>
        )}
        <h1 className="truncate text-xl font-semibold text-aion-text">{title}</h1>
        {subtitle && (
          <p className="mt-1 max-w-2xl text-sm text-aion-muted">{subtitle}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}
