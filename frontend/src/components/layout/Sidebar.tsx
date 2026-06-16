import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Server,
  ShieldAlert,
  Bug,
  FileCode2,
  ClipboardCheck,
  Plug,
  Settings as SettingsIcon,
  Sparkles,
  Boxes,
  GitBranch,
  Network,
  Activity,
  DollarSign,
} from "lucide-react";
import clsx from "clsx";

const NAV = [
  { to: "/", label: "Dashboard", Icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Assets", Icon: Server },
  { to: "/incidents", label: "Incidents", Icon: ShieldAlert },
  { to: "/vulnerabilities", label: "Vulnerabilities", Icon: Bug },
  { to: "/sbom", label: "SBOM", Icon: FileCode2 },
  { to: "/compliance", label: "Compliance", Icon: ClipboardCheck },
  { to: "/integrations", label: "Integrations", Icon: Plug },
  { to: "/settings", label: "Settings", Icon: SettingsIcon },
];

const INFRA_NAV = [
  { to: "/infrastructure", label: "Overview", Icon: LayoutDashboard, end: true },
  { to: "/infrastructure/clusters", label: "Cluster Explorer", Icon: Server },
  { to: "/infrastructure/namespaces", label: "Namespace Explorer", Icon: Boxes },
  { to: "/infrastructure/workloads", label: "Workload Explorer", Icon: GitBranch },
  { to: "/infrastructure/runtime-security", label: "Runtime Security", Icon: ShieldAlert },
  { to: "/infrastructure/topology", label: "Topology", Icon: Network },
  { to: "/infrastructure/cost", label: "Cost Intelligence", Icon: DollarSign },
  { to: "/infrastructure/health", label: "Infrastructure Health", Icon: Activity },
  { to: "/infrastructure/incidents", label: "Infrastructure Incidents", Icon: ShieldAlert },
];

export function Sidebar() {
  return (
    <aside className="flex h-full flex-col">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2 border-b border-aion-border px-4">
        <div className="grid h-7 w-7 place-items-center rounded-md bg-aion-accent/10 ring-1 ring-aion-accent/30">
          <Sparkles className="h-4 w-4 text-aion-accent" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-aion-text">AionUi</div>
          <div className="aion-mono text-[10px] uppercase tracking-wider">
            Command Center
          </div>
        </div>
      </div>

      {/* Tenant switcher (visual placeholder) */}
      <div className="px-3 pt-3">
        <button
          type="button"
          className="w-full rounded-md border border-aion-border bg-aion-surface2 px-3 py-2 text-left text-xs hover:border-aion-accent/40"
        >
          <div className="text-aion-muted">Workspace</div>
          <div className="font-medium text-aion-text">acme-prod</div>
        </button>
      </div>

      {/* Nav */}
      <nav className="mt-4 flex-1 space-y-0.5 overflow-y-auto px-2">
        {NAV.map(({ to, label, Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-aion-accent/10 text-aion-accent ring-1 ring-aion-accent/30"
                  : "text-aion-muted hover:bg-aion-surface2 hover:text-aion-text"
              )
            }
          >
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </NavLink>
        ))}

        {/* Sprint 4 — Infrastructure section */}
        <div className="px-3 pt-4 text-[10px] font-semibold uppercase tracking-wider text-aion-muted">
          Infrastructure
        </div>
        {INFRA_NAV.map(({ to, label, Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-aion-accent/10 text-aion-accent ring-1 ring-aion-accent/30"
                  : "text-aion-muted hover:bg-aion-surface2 hover:text-aion-text"
              )
            }
          >
            <Icon className="h-4 w-4" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer / build info */}
      <div className="border-t border-aion-border p-3 text-[11px] text-aion-muted">
        <div className="flex items-center justify-between">
          <span className="aion-mono">v0.1.0 · sprint-1</span>
          <span className="inline-flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-aion-ok" />
            healthy
          </span>
        </div>
      </div>
    </aside>
  );
}
