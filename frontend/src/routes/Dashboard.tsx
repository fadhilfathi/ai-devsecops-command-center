import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { SecurityScore } from "@/components/security/SecurityScore";
import { RiskHeatmap } from "@/components/security/RiskHeatmap";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { Network } from "lucide-react";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";

/**
 * Dashboard — `/`
 *
 * Sprint 2: top of the page is the Security Score section
 * (composite + 5 sub-metric tiles with sparklines). The original
 * KPIs sit below, and the Risk Heatmap is collapsible.
 */
export function Dashboard() {
  const { data: kpis } = useFetch(api.dashboardKpis, []);
  const [heatmapOpen, setHeatmapOpen] = useState(true);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Posture"
        subtitle="Live view across the estate. Auto-refresh every 30s."
        breadcrumbs={[{ label: "AionUi" }, { label: "Dashboard" }]}
        actions={
          <>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setHeatmapOpen((v) => !v)}
              aria-pressed={heatmapOpen}
            >
              {heatmapOpen ? "Hide" : "Show"} risk heatmap
            </Button>
            <Button size="sm" variant="primary">
              Run scan
            </Button>
          </>
        }
      />

      {/* S2.6 — Security Score Overview */}
      <section aria-label="Security score overview">
        <SecurityScore />
      </section>

      {/* S2.6 — Risk Heatmap (collapsible) */}
      {heatmapOpen && (
        <section aria-label="Risk heatmap">
          <RiskHeatmap />
        </section>
      )}

      {/* Original KPI strip */}
      <section aria-label="Key metrics">
        <KpiGrid>
          {(kpis ?? []).map((k) => (
            <KpiTile key={k.label} kpi={k} />
          ))}
        </KpiGrid>
      </section>

      {/* Quick links */}
      <section className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <QuickLink
          to="/sbom"
          title="Open SBOM viewer"
          hint="Component table with filters and CycloneDX export"
        />
        <QuickLink
          to="/vulnerabilities/timeline"
          title="Vulnerability timeline"
          hint="New CVEs per period, stacked by severity"
        />
        <QuickLink
          to="/graph/default"
          title="Dependency graph"
          hint="Force-directed view of all components"
        />
      </section>
    </div>
  );
}

function QuickLink({
  to,
  title,
  hint,
}: {
  to: string;
  title: string;
  hint: string;
}) {
  return (
    <Card className="aion-card-hover">
      <a
        href={to}
        className="block p-4"
        aria-label={`${title} — ${hint}`}
      >
        <div className="flex items-center justify-between">
          <div className="text-sm font-semibold text-text">{title}</div>
          <Network className="h-4 w-4 text-muted" aria-hidden="true" />
        </div>
        <div className="mt-1 text-xs text-muted">{hint}</div>
      </a>
    </Card>
  );
}
