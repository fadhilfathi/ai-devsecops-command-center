import { FileCode2, Download, Upload } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { titleCase } from "@/lib/format";
import type { SbomComponent } from "@/types";

const columns: Column<SbomComponent>[] = [
  {
    key: "name",
    header: "Component",
    cell: (c) => (
      <div>
        <div className="font-medium text-aion-text">{c.name}</div>
        <div className="aion-mono text-[11px]">{c.purl}</div>
      </div>
    ),
  },
  {
    key: "version",
    header: "Version",
    cell: (c) => <span className="aion-mono">{c.version}</span>,
  },
  {
    key: "license",
    header: "License",
    cell: (c) => <Badge variant="info">{c.license}</Badge>,
  },
  {
    key: "supplier",
    header: "Supplier",
    cell: (c) => <span className="text-aion-muted">{c.supplier ?? "—"}</span>,
  },
  {
    key: "vulns",
    header: "Vulns",
    cell: (c) =>
      c.vulnerabilities > 0 ? (
        <Badge variant="danger">{c.vulnerabilities}</Badge>
      ) : (
        <Badge variant="ok">0</Badge>
      ),
  },
];

export function SBOMPage() {
  const { data } = useFetch(api.sbom, []);

  const totalVulns = (data ?? []).reduce((acc, c) => acc + c.vulnerabilities, 0);
  const licenses = new Set((data ?? []).map((c) => c.license)).size;

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
            <Button size="sm" variant="primary">
              <Download className="h-3.5 w-3.5" /> Export (CycloneDX)
            </Button>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Components</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">
            Unique licenses
          </div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">{licenses}</div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">
            Components w/ vulns
          </div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((c) => c.vulnerabilities > 0).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">
            Total known vulns
          </div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">{totalVulns}</div>
        </Card>
      </div>

      <Card>
        <Card.Header
          title="Components"
          subtitle="All build artifacts in scope of the current workspace."
          actions={
            <Badge variant="info">
              <FileCode2 className="h-3 w-3" /> {titleCase("CycloneDX 1.5")}
            </Badge>
          }
        />
        <Card.Body className="p-0">
          <DataTable
            rows={data ?? []}
            columns={columns}
            rowKey={(c) => c.id}
            empty="No SBOM components ingested yet."
          />
        </Card.Body>
      </Card>
    </div>
  );
}
