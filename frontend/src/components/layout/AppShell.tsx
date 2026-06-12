import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { StatusBar } from "./StatusBar";

/**
 * AppShell — the persistent chrome around every AionUi screen.
 *
 * Layout: a fixed sidebar on the left, a top bar across the top,
 * a status bar at the bottom (system posture / event-bus health),
 * and the routed page rendered in the middle.
 */
export function AppShell() {
  return (
    <div className="grid h-full grid-cols-[260px_1fr] grid-rows-[56px_1fr_28px] bg-aion-bg">
      {/* Sidebar spans the full height on the left. */}
      <div className="row-span-3 border-r border-aion-border bg-aion-surface">
        <Sidebar />
      </div>

      {/* Topbar */}
      <div className="border-b border-aion-border bg-aion-surface">
        <Topbar />
      </div>

      {/* Routed content */}
      <main className="overflow-y-auto">
        <div className="mx-auto max-w-[1600px] p-6">
          <Outlet />
        </div>
      </main>

      {/* Status bar spans the full width at the bottom. */}
      <div className="col-span-2 border-t border-aion-border bg-aion-surface/60">
        <StatusBar />
      </div>
    </div>
  );
}
