import { useState, type ReactNode } from "react";
import { Plug, Github, Cloud, MessagesSquare, Shield, KeyRound, Wrench } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { PageHeader } from "@/components/ui/PageHeader";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtRel, titleCase } from "@/lib/format";
import type { Integration } from "@/types";

const categoryIcon: Record<Integration["category"], ReactNode> = {
  scm: <Github className="h-4 w-4" />,
  ci: <Wrench className="h-4 w-4" />,
  ticketing: <Wrench className="h-4 w-4" />,
  chat: <MessagesSquare className="h-4 w-4" />,
  cloud: <Cloud className="h-4 w-4" />,
  siem: <Shield className="h-4 w-4" />,
  iam: <KeyRound className="h-4 w-4" />,
};

const columns: Column<Integration>[] = [
  {
    key: "name",
    header: "Integration",
    cell: (i) => (
      <div className="flex items-center gap-2">
        <div className="grid h-7 w-7 place-items-center rounded-md border border-aion-border bg-aion-surface2 text-aion-muted">
          {categoryIcon[i.category]}
        </div>
        <div>
          <div className="font-medium text-aion-text">{i.name}</div>
          <div className="aion-mono text-[11px] text-aion-muted">{i.vendor}</div>
        </div>
      </div>
    ),
  },
  {
    key: "cat",
    header: "Category",
    cell: (i) => <Badge variant="neutral">{titleCase(i.category)}</Badge>,
  },
  {
    key: "status",
    header: "Status",
    cell: (i) => (
      <Badge
        variant={
          i.status === "connected"
            ? "ok"
            : i.status === "needs-attention"
              ? "warn"
              : "danger"
        }
      >
        {titleCase(i.status)}
      </Badge>
    ),
  },
  {
    key: "sync",
    header: "Last sync",
    cell: (i) =>
      i.lastSyncAt ? (
        <span className="aion-mono">{fmtRel(i.lastSyncAt)}</span>
      ) : (
        <span className="text-aion-muted">never</span>
      ),
  },
  {
    key: "actions",
    header: "",
    className: "text-right",
    cell: () => (
      <Button size="sm" variant="ghost">
        Configure
      </Button>
    ),
  },
];

export function IntegrationsPage() {
  const { data } = useFetch(api.integrations, []);

  const groups: Integration["category"][] = [
    "scm",
    "ci",
    "ticketing",
    "chat",
    "cloud",
    "siem",
    "iam",
  ];

  return (
    <div>
      <PageHeader
        title="Integrations"
        subtitle="Connect external systems: source control, CI/CD, ticketing, chat, cloud, SIEM, IAM."
        breadcrumbs={[{ label: "AionUi" }, { label: "Integrations" }]}
        actions={
          <Button size="sm" variant="primary">
            <Plug className="h-3.5 w-3.5" /> Add integration
          </Button>
        }
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Connected</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((i) => i.status === "connected").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">
            Needs attention
          </div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((i) => i.status === "needs-attention").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Disconnected</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).filter((i) => i.status === "disconnected").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-[11px] uppercase tracking-wider text-aion-muted">Total</div>
          <div className="mt-1 text-2xl font-semibold text-aion-text">
            {(data ?? []).length}
          </div>
        </Card>
      </div>

      {groups.map((g) => {
        const items = (data ?? []).filter((i) => i.category === g);
        if (items.length === 0) return null;
        return (
          <section key={g} className="mb-6">
            <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-aion-muted">
              {titleCase(g)}
            </h2>
            <DataTable
              rows={items}
              columns={columns}
              rowKey={(i) => i.id}
              empty={`No ${g} integrations.`}
            />
          </section>
        );
      })}
    </div>
  );
}
