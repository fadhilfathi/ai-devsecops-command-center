import { Server, Filter } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel, titleCase } from "@/lib/format";
import type { Asset } from "@/types";

const columns: Column<Asset>[] = [
  {
    key: "name",
    header: "Asset",
    cell: (a) => (
      <div className="flex items-center gap-2">
        <Server className="h-4 w-4 text-aion-muted" />
        <div>
          <div className="font-medium text-aion-text">{a.name}</div>
          <div className="aion-mono text-[11px]">{a.id}</div>
        </div>
      </div>
    ),
  },
  {
    key: "kind",
    header: "Kind",
    cell: (a) => <Badge variant="neutral">{titleCase(a.kind)}</Badge>,
  },
  {
    key: "owner",
    header: "Owner",
    cell: (a) => <span className="aion-mono">{a.owner}</span>,
  },
  {
    key: "env",
    header: "Env",
    cell: (a) => (
      <Badge
        variant={
          a.environment === "prod"
            ? "danger"
            : a.environment === "staging"
              ? "warn"
              : "info"
        }
      >
        {titleCase(a.environment)}
      </Badge>
    ),
  },
  {
    key: "crit",
    header: "Criticality",
    cell: (a) => <Badge severity={a.criticality}>{titleCase(a.criticality)}</Badge>,
  },
  {
    key: "tags",
    header: "Tags",
    cell: (a) => (
      <div className="flex flex-wrap gap-1">
        {a.tags.map((t) => (
          <span
            key={t}
            className="rounded border border-aion-border bg-aion-surface2 px-1.5 py-0.5 text-[10px] text-aion-muted"
          >
            {t}
          </span>
        ))}
      </div>
    ),
  },
  {
    key: "seen",
    header: "Last seen",
    cell: (a) => <span className="aion-mono">{fmtRel(a.lastSeen)}</span>,
  },
];

export function AssetsPage() {
  const { data } = useFetch(api.assets, []);

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle="Unified inventory across repositories, services, identities, and data stores."
        breadcrumbs={[{ label: "AionUi" }, { label: "Assets" }]}
        actions={
          <>
            <Button size="sm" variant="secondary">
              <Filter className="h-3.5 w-3.5" /> Filters
            </Button>
            <Button size="sm" variant="primary">
              + Add asset
            </Button>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Total</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Production</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((a) => a.environment === "prod").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Critical</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((a) => a.criticality === "critical").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Untagged</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((a) => a.tags.length === 0).length}
          </div>
        </Card>
      </div>

      <DataTable
        rows={data ?? []}
        columns={columns}
        rowKey={(a) => a.id}
        empty="No assets match the current filters."
      />
    </div>
  );
}
