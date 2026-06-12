import clsx from "clsx";
import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const variantClasses: Record<Variant, string> = {
  primary:
    "bg-aion-accent text-aion-bg hover:bg-aion-accent/90 focus-visible:ring-aion-accent/40",
  secondary:
    "bg-aion-surface2 text-aion-text border border-aion-border hover:border-aion-accent/40",
  ghost: "text-aion-muted hover:bg-aion-surface2 hover:text-aion-text",
  danger:
    "bg-aion-danger/15 text-aion-danger border border-aion-danger/30 hover:bg-aion-danger/25",
};

const sizeClasses: Record<Size, string> = {
  sm: "h-7 px-2.5 text-xs",
  md: "h-9 px-3.5 text-sm",
};

/**
 * Button — small, opinionated button primitive for AionUi.
 */
export function Button({
  variant = "secondary",
  size = "md",
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors focus:outline-none focus-visible:ring-2 disabled:cursor-not-allowed disabled:opacity-50",
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      {...rest}
    >
      {children}
    </button>
  );
}
