import { Search, Bell, UserCircle2, Command } from "lucide-react";

export function Topbar() {
  return (
    <div className="flex h-14 items-center gap-4 px-4">
      {/* Global search */}
      <div className="relative max-w-md flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-aion-muted" />
        <input
          type="search"
          placeholder="Search assets, CVEs, incidents, controls…"
          className="w-full rounded-md border border-aion-border bg-aion-surface2 py-1.5 pl-9 pr-16 text-sm text-aion-text placeholder:text-aion-muted focus:border-aion-accent/50 focus:outline-none focus:ring-1 focus:ring-aion-accent/30"
        />
        <kbd className="pointer-events-none absolute right-2 top-1/2 inline-flex -translate-y-1/2 items-center gap-1 rounded border border-aion-border bg-aion-bg px-1.5 py-0.5 text-[10px] text-aion-muted">
          <Command className="h-3 w-3" />K
        </kbd>
      </div>

      {/* Right side */}
      <div className="ml-auto flex items-center gap-3">
        <button
          type="button"
          aria-label="Notifications"
          className="relative rounded-md p-2 text-aion-muted hover:bg-aion-surface2 hover:text-aion-text"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-severity-critical" />
        </button>

        <div className="flex items-center gap-2 rounded-md border border-aion-border bg-aion-surface2 px-2 py-1">
          <UserCircle2 className="h-5 w-5 text-aion-muted" />
          <div className="leading-tight">
            <div className="text-xs font-medium text-aion-text">m.chen</div>
            <div className="aion-mono text-[10px]">security-admin</div>
          </div>
        </div>
      </div>
    </div>
  );
}
