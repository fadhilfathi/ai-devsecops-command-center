import { Bug, Search } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtDate, titleCase } from "@/lib/format";
import type { Vulnerability } from "@/types";

const columns: Column<Vulnerability>[] = [
  {
    key: "cve",
    header: "CVE / ID",
    cell: (v) => (
      <div>
        <div className="aion-mono text-aion-text">{v.cve ?? v.id}</div>
        <div className="text-xs text-aion-muted">{v.title}</div>
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
        <div className="font-medium text-aion-text">{v.package}</div>
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
        <span className="text-aion-muted">—</span>
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

export function VulnerabilitiesPage() {
  const { data } = useFetch(api.vulnerabilities, []);

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        subtitle="CVE feed, internal findings, and remediation status across the estate."
        breadcrumbs={[{ label: "AionUi" }, { label: "Vulnerabilities" }]}
        actions={
          <>
            <Button size="sm" variant="secondary">
              <Search className="h-3.5 w-3.5" /> Search CVE
            </Button>
            <Button size="sm" variant="primary">
              <Bug className="h-3.5 w-3.5" /> Scan now
            </Button>
          </>
        }
      />

      {/* Severity summary */}
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        {(
          ["critical", "high", "medium", "low", "info"] as const
        ).map((sev) => {
          const count = (data ?? []).filter((v) => v.severity === sev).length;
          return (
            <Card key={sev} className="p-3">
              <div className="flex items-center justify-between">
                <div className="text-[11px] uppercase tracking-wider text-aion-muted">
                  {titleCase(sev)}
                </div>
                <Badge severity={sev}>{count}</Badge>
              </div>
              <div className="mt-1 text-xl font-semibold text-aion-text">{count}</div>
            </Card>
          );
        })}
      </div>

      <DataTable
        rows={data ?? []}
        columns={columns}
        rowKey={(v) => v.id}
        empty="No vulnerabilities detected."
      />
    </div>
  );
}
