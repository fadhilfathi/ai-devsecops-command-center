import { useState, type ComponentType, type ReactNode } from "react";
import {
  Building2,
  KeyRound,
  ScrollText,
  ShieldCheck,
  Users,
  Webhook,
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { PageHeader } from "@/components/ui/PageHeader";
import { titleCase } from "@/lib/format";

type Section = "org" | "teams" | "rbac" | "policies" | "tokens" | "audit";

const SECTIONS: {
  id: Section;
  label: string;
  Icon: ComponentType<{ className?: string }>;
}[] = [
  { id: "org", label: "Organization", Icon: Building2 },
  { id: "teams", label: "Teams", Icon: Users },
  { id: "rbac", label: "Roles & Access", Icon: ShieldCheck },
  { id: "policies", label: "Policies", Icon: ScrollText },
  { id: "tokens", label: "API Tokens", Icon: KeyRound },
  { id: "audit", label: "Audit Log", Icon: Webhook },
];

export function SettingsPage() {
  const [section, setSection] = useState<Section>("org");

  return (
    <div>
      <PageHeader
        title="Settings"
        subtitle="Workspace configuration, access control, and audit trail."
        breadcrumbs={[{ label: "AionUi" }, { label: "Settings" }]}
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[220px_1fr]">
        {/* Side nav */}
        <nav className="aion-card h-fit p-2">
          {SECTIONS.map(({ id, label, Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setSection(id)}
              className={`flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                section === id
                  ? "bg-aion-accent/10 text-aion-accent"
                  : "text-aion-muted hover:bg-aion-surface2 hover:text-aion-text"
              }`}
            >
              <Icon className="h-4 w-4" /> {label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="space-y-4">
          {section === "org" && <OrgSettings />}
          {section === "teams" && <TeamsSettings />}
          {section === "rbac" && <RbacSettings />}
          {section === "policies" && <PoliciesSettings />}
          {section === "tokens" && <TokensSettings />}
          {section === "audit" && <AuditSettings />}
        </div>
      </div>
    </div>
  );
}

function SectionCard({ title, description, children, actions }: {
  title: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <Card>
      <Card.Header title={title} subtitle={description} actions={actions} />
      <Card.Body>{children}</Card.Body>
    </Card>
  );
}

function Field({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="mb-4 grid grid-cols-1 gap-1 md:grid-cols-[200px_1fr]">
      <div className="text-xs uppercase tracking-wider text-aion-muted">{label}</div>
      <div>
        <div className="rounded-md border border-aion-border bg-aion-surface2 px-3 py-2 text-sm text-aion-text">
          {value}
        </div>
        {hint && <div className="mt-1 text-[11px] text-aion-muted">{hint}</div>}
      </div>
    </div>
  );
}

function OrgSettings() {
  return (
    <SectionCard
      title="Organization"
      description="The top-level workspace. All assets, users, and policies belong to an organization."
    >
      <Field label="Name" value="Acme Corp" />
      <Field label="Slug" value="acme-prod" hint="Used in URLs and CLI." />
      <Field label="Primary region" value="us-east-1" />
      <Field label="Compliance frameworks" value="CISv8, NIST 800-53, SOC 2" />
      <div className="mt-2 flex justify-end">
        <Button variant="primary" size="sm">Save changes</Button>
      </div>
    </SectionCard>
  );
}

function TeamsSettings() {
  const teams = [
    { name: "security-admin", members: 4, scope: "global" },
    { name: "platform", members: 12, scope: "infra" },
    { name: "payments", members: 8, scope: "team:payments" },
    { name: "data", members: 6, scope: "team:data" },
  ];
  return (
    <SectionCard
      title="Teams"
      description="Groups of users with shared scope, used for asset ownership and policies."
      actions={<Button size="sm" variant="primary">+ New team</Button>}
    >
      <ul className="divide-y divide-aion-border">
        {teams.map((t) => (
          <li key={t.name} className="flex items-center justify-between py-3">
            <div>
              <div className="text-sm font-medium text-aion-text">{t.name}</div>
              <div className="aion-mono text-[11px]">scope: {t.scope}</div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant="neutral">{t.members} members</Badge>
              <Button size="sm" variant="ghost">Edit</Button>
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function RbacSettings() {
  const roles = [
    { name: "security-admin", perms: ["*"], users: 4 },
    { name: "compliance-reader", perms: ["compliance:read", "audit:read"], users: 7 },
    { name: "developer", perms: ["assets:read", "vulns:read", "vulns:triage"], users: 84 },
    { name: "incident-responder", perms: ["incidents:*", "assets:read"], users: 6 },
  ];
  return (
    <SectionCard
      title="Roles & access (RBAC)"
      description="Role-based access control. Permissions follow resource:action verbs."
    >
      <ul className="divide-y divide-aion-border">
        {roles.map((r) => (
          <li key={r.name} className="grid grid-cols-1 gap-2 py-3 md:grid-cols-[1.2fr_2fr_auto]">
            <div className="text-sm font-medium text-aion-text">{r.name}</div>
            <div className="flex flex-wrap gap-1">
              {r.perms.map((p) => (
                <span
                  key={p}
                  className="rounded border border-aion-border bg-aion-surface2 px-1.5 py-0.5 aion-mono text-[11px]"
                >
                  {p}
                </span>
              ))}
            </div>
            <div className="flex items-center justify-end gap-3">
              <Badge variant="neutral">{r.users} users</Badge>
              <Button size="sm" variant="ghost">Edit</Button>
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function PoliciesSettings() {
  return (
    <SectionCard
      title="Policies"
      description="Org-wide guardrails evaluated by agent-core and the API gateway."
    >
      <ul className="space-y-2 text-sm">
        {[
          { name: "Block public S3 buckets", state: "enforced" as const },
          { name: "Require MFA for prod access", state: "enforced" as const },
          { name: "Auto-remediate CVSS ≥ 9 within 24h", state: "enforced" as const },
          { name: "Quarantine unmaintained images (>180d)", state: "audit" as const },
        ].map((p) => (
          <li
            key={p.name}
            className="flex items-center justify-between rounded-md border border-aion-border bg-aion-surface2 px-3 py-2"
          >
            <span className="text-aion-text">{p.name}</span>
            <Badge variant={p.state === "enforced" ? "ok" : "info"}>{titleCase(p.state)}</Badge>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function TokensSettings() {
  const tokens = [
    { name: "ci-runner", last: "2 hours ago", scopes: "incidents:write, vulns:read" },
    { name: "github-app", last: "1 minute ago", scopes: "assets:read, vulns:write" },
    { name: "siem-bridge", last: "5 minutes ago", scopes: "events:write" },
  ];
  return (
    <SectionCard
      title="API tokens"
      description="Personal and service-account tokens for programmatic access."
      actions={<Button size="sm" variant="primary">+ Generate token</Button>}
    >
      <ul className="divide-y divide-aion-border">
        {tokens.map((t) => (
          <li key={t.name} className="grid grid-cols-1 gap-1 py-3 md:grid-cols-[1fr_1fr_2fr_auto]">
            <div className="text-sm font-medium text-aion-text">{t.name}</div>
            <div className="aion-mono text-[11px]">used {t.last}</div>
            <div className="aion-mono text-[11px] text-aion-muted">{t.scopes}</div>
            <div className="text-right">
              <Button size="sm" variant="danger">Revoke</Button>
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function AuditSettings() {
  const entries = [
    { ts: "2m ago", actor: "m.chen", action: "role.assign", target: "team:payments / compliance-reader" },
    { ts: "14m ago", actor: "agent:remediator", action: "policy.evaluate", target: "auto-bump xz-utils" },
    { ts: "1h ago", actor: "r.patel", action: "integration.update", target: "Splunk Cloud" },
    { ts: "3h ago", actor: "github-app", action: "pr.comment", target: "aion/aion#2841" },
  ];
  return (
    <SectionCard
      title="Audit log"
      description="Immutable, append-only record of every privileged action in the workspace."
      actions={<Button size="sm" variant="secondary">Export (NDJSON)</Button>}
    >
      <ul className="divide-y divide-aion-border">
        {entries.map((e, i) => (
          <li key={i} className="grid grid-cols-[80px_140px_140px_1fr] items-center gap-3 py-2 text-sm">
            <span className="aion-mono">{e.ts}</span>
            <span className="aion-mono text-aion-text">{e.actor}</span>
            <Badge variant="info">{e.action}</Badge>
            <span className="aion-mono text-aion-muted">{e.target}</span>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}
