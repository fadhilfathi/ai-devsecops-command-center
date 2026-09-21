import { format, formatDistanceToNow, parseISO } from 'date-fns';
import type { Severity } from '@/types';

/** Format an ISO date as a short absolute timestamp. */
export function fmtDate(iso: string): string {
  return format(parseISO(iso), 'yyyy-MM-dd HH:mm');
}

/** "3 minutes ago"-style relative formatter. */
export function fmtRel(iso: string): string {
  return formatDistanceToNow(parseISO(iso), { addSuffix: true });
}

/** Tailwind classes for severity chips. Kept in one place for consistency. */
export function severityClasses(s: Severity): string {
  switch (s) {
    case 'critical':
      return 'bg-severity-critical/15 text-severity-critical border-severity-critical/40';
    case 'high':
      return 'bg-severity-high/15 text-severity-high border-severity-high/40';
    case 'medium':
      return 'bg-severity-medium/15 text-severity-medium border-severity-medium/40';
    case 'low':
      return 'bg-severity-low/15 text-severity-low border-severity-low/40';
    case 'info':
    default:
      return 'bg-severity-info/15 text-severity-info border-severity-info/40';
  }
}

/** Capitalize the first letter — used for labels in tables/badges. */
export function titleCase(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Format a number with thousands separators. */
export function fmtNumber(n: number): string {
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US');
}

/** Format a USD value with $ and thousands separators. */
export function fmtUsd(n: number): string {
  if (!Number.isFinite(n)) return '—';
  return `$${n.toLocaleString('en-US', { maximumFractionDigits: 0 })}`;
}

/** Format bytes as a human-readable string. */
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Format CPU millicores as a human-readable string. */
export function fmtCpu(mc: number): string {
  if (!Number.isFinite(mc)) return '—';
  if (mc < 1000) return `${mc}m`;
  return `${(mc / 1000).toFixed(1)} vCPU`;
}
