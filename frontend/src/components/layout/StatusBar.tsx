import { Activity, Database, Cpu, Radio } from "lucide-react";
import type { ReactNode } from "react";

/**
 * StatusBar — bottom-of-screen system posture. Reflects the live
 * health of the six backend services and the event bus. In Sprint 1
 * these are static indicators; once SRE wires up Prometheus, the
 * values become live.
 */
export function StatusBar() {
  return (
    <div className="flex h-7 items-center gap-4 px-4 text-[11px] text-aion-muted">
      <Item icon={<Activity className="h-3 w-3 text-aion-ok" />} label="gateway" status="ok" />
      <Item icon={<Database className="h-3 w-3 text-aion-ok" />} label="postgres" status="ok" />
      <Item icon={<Cpu className="h-3 w-3 text-aion-ok" />} label="agent-core" status="ok" />
      <Item
        icon={<Radio className="h-3 w-3 text-aion-warn" />}
        label="event-bus"
        status="degraded"
      />
      <span className="ml-auto aion-mono">build 0.1.0 · region us-east-1</span>
    </div>
  );
}

function Item({
  icon,
  label,
  status,
}: {
  icon: ReactNode;
  label: string;
  status: "ok" | "degraded" | "down";
}) {
  const dot =
    status === "ok"
      ? "bg-aion-ok"
      : status === "degraded"
        ? "bg-aion-warn"
        : "bg-aion-danger";
  return (
    <span className="inline-flex items-center gap-1.5">
      {icon}
      <span className="text-aion-text/80">{label}</span>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
    </span>
  );
}
