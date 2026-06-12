import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

/**
 * EmptyState — placeholder for empty lists / tables / search results.
 */
export function EmptyState({
  title,
  description,
  action,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="grid place-items-center gap-3 p-10 text-center">
      <div className="grid h-10 w-10 place-items-center rounded-md border border-aion-border bg-aion-surface2 text-aion-muted">
        <Inbox className="h-5 w-5" />
      </div>
      <div>
        <div className="text-sm font-medium text-aion-text">{title}</div>
        {description && (
          <div className="mt-0.5 text-xs text-aion-muted">{description}</div>
        )}
      </div>
      {action}
    </div>
  );
}
