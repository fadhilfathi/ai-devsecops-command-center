import { useState } from "react";
import { FileCode2, Download, Upload, List, Network } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { SbomViewer } from "@/components/security/SbomViewer";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { titleCase } from "@/lib/format";

/**
 * SBOM — `/sbom`
 *
 * Sprint 2: the page renders a list of available SBOMs (cards) plus
 * the active viewer (SbomViewer). When the backend exposes SBOM
 * listings, we deep-link to `/sbom/:id`; until then we render the
 * primary SBOM inline.
 */
export function SBOM() {
  // For the Sprint-2 skeleton, treat the "default" SBOM as the active
  // one. The list-of-SBOMs metadata comes from the lightweight endpoint
  // — when that ships, replace this with `useFetch(api.sbomList)`.
  const [activeId, setActiveId] = useState<string>("default");
  const { data } = useFetch(api.sbom, []);

  const exportCurrent = () => {
    const url = api.sbomExportUrl(activeId);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${activeId}.cyclonedx.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div>
      <PageHeader
        title="Software Bill of Materials"
        subtitle="CycloneDX / SPDX inventory across all build artifacts."
        breadcrumbs={[{ label: "AionUi" }, { label: "SBOM" }]}
        actions={
          <>
            <Button size="sm" variant="secondary">
              <Upload className="h-3.5 w-3.5" /> Import SBOM
            </Button>
            <Button size="sm" variant="primary" onClick={exportCurrent}>
              <Download className="h-3.5 w-3.5" /> Export CycloneDX
            </Button>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-[280px_1fr]">
        {/* SBOM list (assets/SBOMs) */}
        <Card>
          <Card.Header
            title="Available SBOMs"
            subtitle="Per-asset generated inventories"
          />
          <Card.Body className="p-0">
            <ul className="divide-y divide-border">
              {[
                { id: "default",          name: "checkout-api (current)",     count: 124 },
                { id: "sbom-web-app",     name: "web-app",                     count: 89 },
                { id: "sbom-gateway",     name: "aion-gateway",                count: 41 },
                { id: "sbom-runners",     name: "ci-runner-pool",              count: 67 },
                { id: "sbom-marketing",   name: "marketing-site",              count: 38 },
              ].map((s) => {
                const on = activeId === s.id;
                return (
                  <li key={s.id}>
                    <button
                      type="button"
                      onClick={() => setActiveId(s.id)}
                      aria-pressed={on}
                      className={`flex w-full items-center justify-between gap-2 px-4 py-2.5 text-left text-sm transition-colors ${
                        on
                          ? "bg-accent/10 text-accent"
                          : "hover:bg-surface-2 text-text"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <FileCode2 className="h-4 w-4 text-muted" />
                        <span>
                          <span className="block">{s.name}</span>
                          <span className="aion-mono block text-[10px] text-muted">
                            {s.id}
                          </span>
                        </span>
                      </span>
                      <Badge variant="neutral">{s.count}</Badge>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card.Body>
        </Card>

        {/* Active viewer */}
        <div>
          {data && (
            <div className="mb-3 flex items-center gap-2 text-sm text-muted">
              <List className="h-4 w-4" />
              <span>
                Listing <span className="text-text">{data.length}</span> components
                in the lightweight index
              </span>
            </div>
          )}

          <SbomViewer sbomId={activeId} />

          <div className="mt-4 flex items-center gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() =>
                window.location.assign(`/graph/${encodeURIComponent(activeId)}`)
              }
            >
              <Network className="h-3.5 w-3.5" /> Open dependency graph
            </Button>
            <span className="aion-mono text-[11px] text-muted">
              {titleCase("CycloneDX 1.5")} · {data?.length ?? 0} indexed
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
