import clsx from "clsx";
import type { HTMLAttributes, ReactNode } from "react";

/**
 * Card — base surface primitive for AionUi panels.
 *
 * Use `Card.Header` / `Card.Body` / `Card.Footer` for the common
 * 3-zone layout. Keep titles short and unambiguous; this is a
 * dense ops UI, not marketing.
 */
export function Card({
  className,
  children,
  ...rest
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx("aion-card", className)}
      {...rest}
    >
      {children}
    </div>
  );
}

function Header({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-aion-border px-4 py-3">
      <div className="min-w-0">
        <div className="truncate text-sm font-semibold text-aion-text">
          {title}
        </div>
        {subtitle && (
          <div className="mt-0.5 text-xs text-aion-muted">{subtitle}</div>
        )}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </div>
  );
}

function Body({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("p-4", className)}>{children}</div>;
}

function Footer({ children }: { children: ReactNode }) {
  return (
    <div className="border-t border-aion-border px-4 py-2 text-xs text-aion-muted">
      {children}
    </div>
  );
}

Card.Header = Header;
Card.Body = Body;
Card.Footer = Footer;
