import { useSearchParams } from "react-router-dom";
import { Activity, Bug, FileCode2 } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { VulnTimeline } from "@/components/security/VulnTimeline";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtDate, titleCase } from "@/lib/format";
import type { Severity, Vulnerability } from "@/types";

type View = "list" | "timeline";

const severityCols: Column<Vulnerability>[] = [
  {
    key: "cve",
    header: "CVE / ID",
    cell: (v) => (
      <div>
        <div className="aion-mono text-text">{v.cve ?? v.id}</div>
        <div className="text-xs text-muted">{v.title}</div>
      </div>
    ),
  },
  {
    key: "sev",
    header: "Severity",
    cell: (v) => <Badge severity={v.severity}>{titleCase(v.severity)}</Badge>,
  },
  {
    key: "cvss",
    header: "CVSS",
    cell: (v) => <span className="aion-mono">{v.cvss.toFixed(1)}</span>,
  },
  {
    key: "pkg",
    header: "Package",
    cell: (v) => (
      <div>
        <div className="font-medium text-text">{v.package}</div>
        <div className="aion-mono text-[11px]">@ {v.version}</div>
      </div>
    ),
  },
  {
    key: "fix",
    header: "Fixed in",
    cell: (v) =>
      v.fixedIn ? (
        <span className="aion-mono">{v.fixedIn}</span>
      ) : (
        <span className="text-muted">—</span>
      ),
  },
  {
    key: "status",
    header: "Status",
    cell: (v) => (
      <Badge
        variant={
          v.status === "remediated"
            ? "ok"
            : v.status === "accepted"
              ? "info"
              : v.status === "in-progress"
                ? "warn"
                : "danger"
        }
      >
        {titleCase(v.status)}
      </Badge>
    ),
  },
  {
    key: "detected",
    header: "Detected",
    cell: (v) => <span className="aion-mono">{fmtDate(v.detectedAt)}</span>,
  },
];

/**
 * Vulnerabilities — `/vulnerabilities` and `/vulnerabilities/timeline`
 *
 * Sprint 2: sub-route via `?view=timeline` for the timeline view.
 * Default view is the list. Deep links from the RiskHeatmap use
 * `?ecosystem=X&severity=Y` which we surface as applied filters.
 */
export function Vulnerabilities() {
  const [params, setParams] = useSearchParams();
  const view = (params.get("view") === "timeline" ? "timeline" : "list") as View;
  const eco = params.get("ecosystem");
  const sev = params.get("severity") as Severity | null;

  const setView = (v: View) => {
    const next = new URLSearchParams(params);
    if (v === "list") next.delete("view");
    else next.set("view", v);
    setParams(next, { replace: true });
  };

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        subtitle="CVE feed, internal findings, and remediation status across the estate."
        breadcrumbs={[{ label: "AionUi" }, { label: "Vulnerabilities" }]}
        actions={
          <div
            role="tablist"
            aria-label="Vulnerabilities views"
            className="inline-flex rounded-md border border-border bg-surface-2 p-0.5"
          >
            <TabButton
              active={view === "list"}
              onClick={() => setView("list")}
              icon={<Bug className="h-3.5 w-3.5" />}
            >
              List
            </TabButton>
            <TabButton
              active={view === "timeline"}
              onClick={() => setView("timeline")}
              icon={<Activity className="h-3.5 w-3.5" />}
            >
              Timeline
            </TabButton>
          </div>
        }
      />

      {view === "timeline" ? (
        <div className="space-y-3">
          <VulnTimeline />
          {eco && sev && (
            <div className="aion-mono text-[11px] text-muted">
              showing context for ecosystem <span className="text-text">{eco}</span>,
              severity <span className="text-text">{sev}</span>
            </div>
          )}
        </div>
      ) : (
        <ListView eco={eco} sev={sev} />
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
        active ? "bg-accent/15 text-accent" : "text-muted hover:text-text"
      }`}
    >
      {icon}
      {children}
    </button>
  );
}

function ListView({ eco, sev }: { eco: string | null; sev: Severity | null }) {
  const { data } = useFetch(api.vulnerabilities, []);

  // Apply heatmap-deeplink filters (in a real app this is server-side;
  // for the skeleton we filter client-side over the mock).
  const filtered = (data ?? []).filter((v) => {
    if (sev && v.severity !== sev) return false;
    // ecosystem filter maps approximately via package name; mock doesn't
    // carry ecosystem on Vulnerability, so we leave this as a no-op in
    // the skeleton. Real backend will filter server-side.
    void eco;
    return true;
  });

  return (
    <>
      {(eco || sev) && (
        <Card className="mb-4">
          <Card.Body className="flex items-center gap-2 text-sm">
            <FileCode2 className="h-4 w-4 text-muted" />
            <span className="text-muted">Active filters from risk heatmap:</span>
            {eco && <Badge variant="info">ecosystem: {eco}</Badge>}
            {sev && <Badge severity={sev}>severity: {sev}</Badge>}
          </Card.Body>
        </Card>
      )}

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => {
          const count = (data ?? []).filter((v) => v.severity === s).length;
          return (
            <Card key={s} className="p-3">
              <div className="flex items-center justify-between">
                <div className="text-[11px] uppercase tracking-wider text-muted">
                  {titleCase(s)}
                </div>
                <Badge severity={s}>{count}</Badge>
              </div>
              <div className="mt-1 text-xl font-semibold text-text">{count}</div>
            </Card>
          );
        })}
      </div>

      <DataTable
        rows={filtered}
        columns={severityCols}
        rowKey={(v) => v.id}
        empty="No vulnerabilities match the current filters."
      />
    </>
  );
}
