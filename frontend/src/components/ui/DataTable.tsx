import clsx from "clsx";
import type { ReactNode } from "react";

export type Column<T> = {
  key: string;
  header: ReactNode;
  /** Render the cell. Use this instead of `accessor` for full control. */
  cell: (row: T) => ReactNode;
  /** Tailwind classes for the column (e.g. "w-32 text-right"). */
  className?: string;
  /** Tailwind classes for the header cell. */
  headerClassName?: string;
};

/**
 * DataTable — generic, dependency-free table for AionUi lists.
 *
 * Keep it small and obvious. For large virtualized lists, swap with
 * `@tanstack/react-table` later — the column shape will not change.
 */
export function DataTable<T>({
  rows,
  columns,
  empty,
  rowKey,
  onRowClick,
}: {
  rows: T[];
  columns: Column<T>[];
  empty?: ReactNode;
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
}) {
  if (rows.length === 0) {
    return (
      <div className="aion-card grid place-items-center p-10 text-sm text-aion-muted">
        {empty ?? "No results."}
      </div>
    );
  }

  return (
    <div className="aion-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-aion-border bg-aion-surface2 text-left text-[11px] uppercase tracking-wider text-aion-muted">
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={clsx(
                    "whitespace-nowrap px-4 py-2 font-medium",
                    c.headerClassName
                  )}
                >
                  {c.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={clsx(
                  "border-b border-aion-border/60 last:border-0",
                  onRowClick && "cursor-pointer hover:bg-aion-surface2"
                )}
              >
                {columns.map((c) => (
                  <td key={c.key} className={clsx("px-4 py-2 align-middle", c.className)}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
