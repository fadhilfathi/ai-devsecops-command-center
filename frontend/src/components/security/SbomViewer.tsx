import { useMemo, useState } from "react";
import { FixedSizeList, type ListChildComponentProps } from "react-window";
import { Download, Filter, Search, X } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel, severityClasses, titleCase } from "@/lib/format";
import type { Ecosystem, SbomComponentEnhanced, Severity } from "@/types";

const ECOSYSTEMS: Ecosystem[] = [
  "npm", "pypi", "maven", "go", "rubygems", "cargo", "nuget", "other",
];

const ROW_HEIGHT = 56;

/**
 * SbomViewer — virtualized component table for the SBOM page.
 *
 * Sprint 2 / S2.6 visualization #1. Consumes `GET /api/sbom/{id}` (S2.5).
 * Filters: ecosystem, license, max depth. Search by component name.
 * Export: CycloneDX JSON via a data URL when mocks are on, or a real
 * `/api/sbom/{id}/export?format=cyclonedx-1.5` URL in production.
 *
 * Virtualization: react-window. Row height fixed at 44px.
 */
export function SbomViewer({ sbomId }: { sbomId: string }) {
  const { data, loading } = useFetch(() => api.sbomDocument(sbomId), [sbomId]);

  const [search, setSearch] = useState("");
  const [ecosystemFilter, setEcosystemFilter] = useState<Set<Ecosystem>>(new Set());
  const [licenseFilter, setLicenseFilter] = useState<string | null>(null);
  const [maxDepth, setMaxDepth] = useState<number | null>(null);

  const components = data?.components ?? [];
  const licenses = useMemo(
    () => Array.from(new Set(components.map((c) => c.license))).sort(),
    [components]
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return components.filter((c) => {
      if (q && !c.name.toLowerCase().includes(q)) return false;
      if (ecosystemFilter.size > 0 && !ecosystemFilter.has(c.ecosystem)) return false;
      if (licenseFilter && c.license !== licenseFilter) return false;
      if (maxDepth != null && c.depth > maxDepth) return false;
      return true;
    });
  }, [components, search, ecosystemFilter, licenseFilter, maxDepth]);

  const handleExport = () => {
    const url = api.sbomExportUrl(sbomId);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${sbomId}.cyclonedx.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const clearFilters = () => {
    setSearch("");
    setEcosystemFilter(new Set());
    setLicenseFilter(null);
    setMaxDepth(null);
  };

  const filtersActive =
    search !== "" ||
    ecosystemFilter.size > 0 ||
    licenseFilter != null ||
    maxDepth != null;

  return (
    <div>
      {/* Header */}
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-text">
            {data?.assetName ?? "SBOM"}
          </h2>
          <p className="aion-mono text-[11px]">
            {data
              ? `${data.format} · ${data.componentCount} components · generated ${fmtRel(data.generatedAt)}`
              : "loading…"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={handleExport}>
            <Download className="h-3.5 w-3.5" /> Export CycloneDX
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="aion-card mb-3 p-3">
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_auto_auto_auto_auto]">
          {/* Search */}
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted"
              aria-hidden="true"
            />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search component name…"
              aria-label="Search component name"
              className="w-full rounded-md border border-border bg-surface-2 py-1.5 pl-8 pr-3 text-sm text-text placeholder:text-muted focus:border-accent/50 focus:outline-none focus:ring-1 focus:ring-accent/30"
            />
          </div>

          {/* Ecosystem */}
          <FilterPill label="Ecosystem" active={ecosystemFilter.size > 0}>
            <EcosystemMenu
              selected={ecosystemFilter}
              onChange={setEcosystemFilter}
            />
          </FilterPill>

          {/* License */}
          <FilterPill label="License" active={licenseFilter != null}>
            <select
              value={licenseFilter ?? ""}
              onChange={(e) => setLicenseFilter(e.target.value || null)}
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text focus:border-accent/50 focus:outline-none"
              aria-label="Filter by license"
            >
              <option value="">All</option>
              {licenses.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </FilterPill>

          {/* Depth */}
          <FilterPill label="Depth" active={maxDepth != null}>
            <select
              value={maxDepth ?? ""}
              onChange={(e) =>
                setMaxDepth(e.target.value === "" ? null : Number(e.target.value))
              }
              className="rounded-md border border-border bg-surface-2 px-2 py-1 text-xs text-text focus:border-accent/50 focus:outline-none"
              aria-label="Filter by maximum depth"
            >
              <option value="">All</option>
              <option value="0">Direct only</option>
              <option value="1">≤ 1</option>
              <option value="2">≤ 2</option>
              <option value="3">≤ 3</option>
            </select>
          </FilterPill>

          {filtersActive && (
            <Button size="sm" variant="ghost" onClick={clearFilters}>
              <X className="h-3.5 w-3.5" /> Clear
            </Button>
          )}
        </div>

        <div className="mt-2 aion-mono text-[11px]">
          showing {filtered.length} / {components.length} components
        </div>
      </div>

      {/* Virtualized table */}
      <Card className="overflow-hidden">
        <HeaderRow />
        {loading || !data ? (
          <div className="grid place-items-center p-10 text-sm text-muted">
            Loading components…
          </div>
        ) : filtered.length === 0 ? (
          <div className="grid place-items-center p-10 text-sm text-muted">
            No components match the current filters.
          </div>
        ) : (
          <FixedSizeList
            height={Math.min(560, Math.max(ROW_HEIGHT * 4, filtered.length * ROW_HEIGHT))}
            width="100%"
            itemCount={filtered.length}
            itemSize={ROW_HEIGHT}
            itemData={filtered}
            overscanCount={6}
          >
            {Row}
          </FixedSizeList>
        )}
      </Card>
    </div>
  );
}

// -------------------------------------------------------------------------
// Internals
// -------------------------------------------------------------------------

const COLS = [
  { key: "name",   header: "Component",  width: "minmax(220px,2fr)" },
  { key: "ver",    header: "Version",    width: "110px" },
  { key: "eco",    header: "Ecosystem",  width: "100px" },
  { key: "lic",    header: "License",    width: "120px" },
  { key: "depth",  header: "Depth",      width: "70px" },
  { key: "vulns",  header: "Vulns",      width: "180px" },
] as const;

const GRID_TEMPLATE = COLS.map((c) => c.width).join(" ");

function HeaderRow() {
  return (
    <div
      role="row"
      className="grid items-center gap-3 border-b border-border bg-surface-2 px-4 py-2 text-[11px] uppercase tracking-wider text-muted"
      style={{ gridTemplateColumns: GRID_TEMPLATE }}
    >
      {COLS.map((c) => (
        <div key={c.key} role="columnheader">
          {c.header}
        </div>
      ))}
    </div>
  );
}

const Row = ({ index, style, data }: ListChildComponentProps<SbomComponentEnhanced[]>) => {
  const c = data[index];
  return (
    <div
      style={{ ...style, gridTemplateColumns: GRID_TEMPLATE }}
      role="row"
      className="grid items-center gap-3 overflow-hidden border-b border-border/60 px-4 text-sm hover:bg-surface-2"
    >
      <div role="cell" className="truncate">
        <div className="truncate font-medium text-text">{c.name}</div>
        <div className="aion-mono truncate text-[11px]">{c.purl}</div>
      </div>
      <div role="cell" className="aion-mono text-text">{c.version}</div>
      <div role="cell">
        <Badge variant="neutral">{c.ecosystem}</Badge>
      </div>
      <div role="cell" className="text-text">{c.license}</div>
      <div role="cell" className="aion-mono text-muted">{c.depth}</div>
      <div role="cell">
        {c.vulnerabilities > 0 ? (
          <div className="inline-flex items-center gap-2">
            <SeverityChip severity={c.highestSeverity ?? "medium"} />
            <span className="aion-mono">{c.vulnerabilities}</span>
          </div>
        ) : (
          <Badge variant="ok">0</Badge>
        )}
      </div>
    </div>
  );
};

function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex w-fit items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${severityClasses(severity)}`}
    >
      {titleCase(severity)}
    </span>
  );
}

function FilterPill({
  label,
  active,
  children,
}: {
  label: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`flex items-center gap-1.5 rounded-md border bg-surface-2 px-2 py-1 ${
        active ? "border-accent/40" : "border-border"
      }`}
    >
      <Filter className="h-3 w-3 text-muted" aria-hidden="true" />
      <span className="text-[10px] uppercase tracking-wider text-muted">{label}</span>
      {children}
    </div>
  );
}

function EcosystemMenu({
  selected,
  onChange,
}: {
  selected: Set<Ecosystem>;
  onChange: (next: Set<Ecosystem>) => void;
}) {
  const toggle = (e: Ecosystem) => {
    const next = new Set(selected);
    if (next.has(e)) next.delete(e);
    else next.add(e);
    onChange(next);
  };
  return (
    <div className="flex flex-wrap items-center gap-1">
      {ECOSYSTEMS.map((e) => {
        const on = selected.has(e);
        return (
          <button
            key={e}
            type="button"
            onClick={() => toggle(e)}
            className={`rounded border px-1.5 py-0.5 text-[10px] ${
              on
                ? "border-accent/50 bg-accent/10 text-accent"
                : "border-border bg-surface text-muted hover:border-accent/30"
            }`}
            aria-pressed={on}
          >
            {e}
          </button>
        );
      })}
    </div>
  );
}
