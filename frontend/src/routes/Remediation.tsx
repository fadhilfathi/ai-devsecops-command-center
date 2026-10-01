import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  ClipboardList,
  ExternalLink,
  GitPullRequest,
  Package,
  Play,
} from 'lucide-react';
import { PageHeader } from '@/components/ui/PageHeader';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { EmptyState } from '@/components/ui/EmptyState';
import { api, toAgentFinding } from '@/lib/api';
import { useFetch } from '@/hooks/useFetch';
import { fmtDate, titleCase } from '@/lib/format';
import type {
  ApplyResult,
  Bump,
  Integration,
  PerFindingScore,
  RemediationProposal,
  RemediationResult,
  RemediationRisk,
  TriageDecision,
  TriagePriority,
  TriageResult,
} from '@/types';

type View = 'triage' | 'proposals' | 'apply';

/** Outcome of one pipeline run — `ok` even when the agent had nothing to do
 * (empty findings → null results); `error` when a task call failed. */
type RunResult =
  | {
      status: 'ok';
      triage: TriageResult | null;
      remediation: RemediationResult | null;
    }
  | { status: 'error'; message: string };

/**
 * Remediation — `/remediation`
 *
 * S11-3: triage → proposals → apply. The run action maps the current
 * vulnerability findings through `toAgentFinding` and kicks the agent
 * tasks `triage.findings` + `remediation.propose`; the Apply tab submits
 * `remediation.apply` for one proposal. Tabs are URL-addressable:
 * `?view=triage` (default), `?view=proposals`, `?view=apply`.
 */
export function Remediation() {
  const [params, setParams] = useSearchParams();
  const raw = params.get('view');
  const view: View = raw === 'proposals' || raw === 'apply' ? raw : 'triage';

  const setView = (v: View) => {
    const next = new URLSearchParams(params);
    if (v === 'triage') next.delete('view');
    else next.set('view', v);
    setParams(next, { replace: true });
  };

  const [runId, setRunId] = useState(0);
  const { data: run, loading } = useFetch<RunResult | null>(runPipeline, null, [runId]);
  const remediation = run?.status === 'ok' ? run.remediation : null;

  return (
    <div>
      <PageHeader
        title="Remediation"
        subtitle="Triage findings, review dependency-bump proposals, and open fixes through your integrations."
        breadcrumbs={[{ label: 'AionUi' }, { label: 'Remediation' }]}
        actions={
          <>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setRunId((id) => id + 1)}
              disabled={loading}
            >
              <Play className="h-3.5 w-3.5" />
              {loading ? 'Running…' : 'Run'}
            </Button>
            <div
              role="tablist"
              aria-label="Remediation views"
              className="inline-flex rounded-md border border-border bg-surface-2 p-0.5"
            >
              <TabButton
                active={view === 'triage'}
                onClick={() => setView('triage')}
                icon={<ClipboardList className="h-3.5 w-3.5" />}
              >
                Triage
              </TabButton>
              <TabButton
                active={view === 'proposals'}
                onClick={() => setView('proposals')}
                icon={<Package className="h-3.5 w-3.5" />}
              >
                Proposals
              </TabButton>
              <TabButton
                active={view === 'apply'}
                onClick={() => setView('apply')}
                icon={<GitPullRequest className="h-3.5 w-3.5" />}
              >
                Apply
              </TabButton>
            </div>
          </>
        }
      />

      {view === 'triage' && <TriageTab run={run} loading={loading} />}
      {view === 'proposals' && <ProposalsTab run={run} loading={loading} />}
      {view === 'apply' && <ApplyTab remediation={remediation} loading={loading} />}
    </div>
  );
}

/** Map `api.vulnerabilities()` rows onto the agent finding input and run
 * both analysis tasks. Errors are folded into the result so a re-run always
 * supersedes a previous failure (useFetch keeps a sticky `error`). */
async function runPipeline(): Promise<RunResult> {
  try {
    const findings = (await api.vulnerabilities()).map(toAgentFinding);
    if (findings.length === 0) return { status: 'ok', triage: null, remediation: null };
    const [triage, remediation] = await Promise.all([
      api.triageFindings(findings),
      api.remediationProposals(findings),
    ]);
    return { status: 'ok', triage, remediation };
  } catch (err) {
    return { status: 'error', message: err instanceof Error ? err.message : String(err) };
  }
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
        active ? 'bg-accent/15 text-accent' : 'text-muted hover:text-text'
      }`}
    >
      {icon}
      {children}
    </button>
  );
}

function LoadingCard({ label }: { label: string }) {
  return (
    <Card>
      <Card.Body className="text-sm text-muted">{label}</Card.Body>
    </Card>
  );
}

function ErrorCard({ message }: { message: string }) {
  return (
    <Card>
      <Card.Body className="flex items-center gap-2 text-sm text-aion-danger">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span>{message}</span>
      </Card.Body>
    </Card>
  );
}

const decisionVariant: Record<TriageDecision, 'danger' | 'warn' | 'info'> = {
  open_incident: 'danger',
  create_ticket: 'warn',
  log_only: 'info',
};

const priorityVariant: Record<TriagePriority, 'danger' | 'warn' | 'info' | 'neutral'> = {
  P1: 'danger',
  P2: 'warn',
  P3: 'info',
  P4: 'neutral',
};

const bumpVariant: Record<Bump, 'ok' | 'info' | 'warn' | 'neutral'> = {
  none: 'neutral',
  patch: 'ok',
  minor: 'info',
  major: 'warn',
  unknown: 'neutral',
};

const riskVariant: Record<RemediationRisk, 'ok' | 'warn' | 'danger'> = {
  low: 'ok',
  medium: 'warn',
  high: 'danger',
};

const scoreCols: Column<PerFindingScore>[] = [
  {
    key: 'id',
    header: 'Finding',
    cell: (s) => <span className="aion-mono text-text">{s.id ?? '—'}</span>,
  },
  {
    key: 'score',
    header: 'Score',
    cell: (s) => <span className="aion-mono">{s.score.toFixed(1)}</span>,
  },
  {
    key: 'priority',
    header: 'Priority',
    cell: (s) => <Badge variant={priorityVariant[s.priority]}>{s.priority}</Badge>,
  },
];

function TriageTab({ run, loading }: { run: RunResult | null; loading: boolean }) {
  if (loading) return <LoadingCard label="Running triage…" />;
  if (run?.status === 'error') return <ErrorCard message={run.message} />;
  const t = run?.status === 'ok' ? run.triage : null;
  if (!t) {
    return (
      <EmptyState
        title="Nothing to triage"
        description="No open findings for this tenant — run again after new scans land."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Card className="p-3">
          <div className="text-[11px] uppercase tracking-wider text-muted">Decision</div>
          <div className="mt-2">
            <Badge variant={decisionVariant[t.decision]}>
              {titleCase(t.decision.replace(/_/g, ' '))}
            </Badge>
          </div>
        </Card>
        <Card className="p-3">
          <div className="text-[11px] uppercase tracking-wider text-muted">Priority</div>
          <div className="mt-2">
            <Badge variant={priorityVariant[t.priority]}>{t.priority}</Badge>
          </div>
        </Card>
        {(
          [
            ['Total', t.counts.total],
            ['Critical', t.counts.critical],
            ['High', t.counts.high],
          ] as const
        ).map(([label, count]) => (
          <Card key={label} className="p-3">
            <div className="text-[11px] uppercase tracking-wider text-muted">{label}</div>
            <div className="mt-1 text-xl font-semibold text-text">{count}</div>
          </Card>
        ))}
      </div>

      <Card>
        <Card.Header
          title="Rationale"
          subtitle={`engine ${t.engine} · triaged ${fmtDate(t.triagedAt)}`}
        />
        <Card.Body>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
            {t.rationale.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </Card.Body>
      </Card>

      <div>
        <div className="mb-2 text-sm font-semibold text-text">Per-finding scores</div>
        <DataTable
          rows={t.perFinding}
          columns={scoreCols}
          rowKey={(s) => s.id ?? String(s.score)}
          empty="No findings scored."
        />
      </div>
    </div>
  );
}

const proposalKey = (p: RemediationProposal) => `${p.package.name}@${p.to}`;

const proposalCols: Column<RemediationProposal>[] = [
  {
    key: 'package',
    header: 'Package',
    cell: (p) => (
      <div>
        <div className="font-medium text-text">{p.package.name}</div>
        <div className="mt-0.5 flex items-center gap-1.5">
          <Badge variant="neutral">{p.package.ecosystem}</Badge>
          {p.status === 'manual_review' && <Badge variant="warn">manual review</Badge>}
        </div>
      </div>
    ),
  },
  {
    key: 'bumpTo',
    header: 'From → To',
    cell: (p) => (
      <span className="aion-mono text-[11px]">
        {p.from} → {p.to}
      </span>
    ),
  },
  {
    key: 'bump',
    header: 'Bump',
    cell: (p) => <Badge variant={bumpVariant[p.bump]}>{p.bump}</Badge>,
  },
  {
    key: 'risk',
    header: 'Risk',
    cell: (p) => <Badge variant={riskVariant[p.risk]}>{titleCase(p.risk)}</Badge>,
  },
  {
    key: 'resolves',
    header: 'Resolves',
    cell: (p) => (
      <div className="aion-mono text-[11px] text-muted">{p.resolves.join(', ') || '—'}</div>
    ),
  },
  {
    key: 'hint',
    header: 'Manifest hint',
    cell: (p) => (
      <code className="aion-mono rounded bg-surface-2 px-2 py-1 text-[11px] text-text">
        {p.manifestHint}
      </code>
    ),
  },
];

function ProposalsTab({ run, loading }: { run: RunResult | null; loading: boolean }) {
  if (loading) return <LoadingCard label="Generating proposals…" />;
  if (run?.status === 'error') return <ErrorCard message={run.message} />;
  const r = run?.status === 'ok' ? run.remediation : null;
  if (!r) {
    return (
      <EmptyState
        title="No proposals yet"
        description="No findings produced a dependency bump — run again after new scans land."
      />
    );
  }

  return (
    <div className="space-y-4">
      <DataTable
        rows={r.proposals}
        columns={proposalCols}
        rowKey={proposalKey}
        empty="No bump proposals for the current findings."
      />

      {r.unresolved.length > 0 && (
        <Card>
          <Card.Header
            title="Unresolved"
            subtitle={`${r.unresolved.length} package(s) without a proposed fix · engine ${r.engine} · ${fmtDate(r.generatedAt)}`}
          />
          <Card.Body>
            <ul className="space-y-2 text-sm">
              {r.unresolved.map((u) => (
                <li key={u.package.name}>
                  <div className="flex items-center gap-1.5">
                    <span className="aion-mono text-text">{u.package.name}</span>
                    <Badge variant="neutral">{u.package.ecosystem}</Badge>
                  </div>
                  <div className="text-xs text-muted">{u.reason}</div>
                </li>
              ))}
            </ul>
          </Card.Body>
        </Card>
      )}
    </div>
  );
}

function ApplyTab({
  remediation,
  loading,
}: {
  remediation: RemediationResult | null;
  loading: boolean;
}) {
  const proposals = remediation?.proposals ?? [];
  const { data: integrations, loading: integrationsLoading } = useFetch<Integration[]>(
    api.integrations,
    [],
    [],
  );
  const [selectedKey, setSelectedKey] = useState('');
  const [integrationId, setIntegrationId] = useState<string | null>(null);
  const [dryRun, setDryRun] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);

  // "Resolved" default: the first connected SCM integration (the apply path
  // opens a GitHub issue/PR via integration-service), else the first one.
  const resolvedIntegrationId =
    (integrations.find((i) => i.category === 'scm' && i.status === 'connected') ?? integrations[0])
      ?.id ?? '';
  const effectiveIntegrationId = integrationId ?? resolvedIntegrationId;
  const selected = proposals.find((p) => proposalKey(p) === selectedKey) ?? proposals[0];

  // A run in flight has no remediation result yet — show the loading card
  // instead of a false "run the pipeline first" empty state.
  if (loading) return <LoadingCard label="Running pipeline…" />;

  if (proposals.length === 0) {
    return (
      <EmptyState
        title="No proposals to apply"
        description="Run the pipeline first — apply needs a remediation proposal."
      />
    );
  }

  const submit = async () => {
    if (!effectiveIntegrationId) return;
    setSubmitting(true);
    setApplyError(null);
    setApplyResult(null);
    try {
      setApplyResult(
        await api.applyRemediation({
          integrationId: effectiveIntegrationId,
          proposal: selected,
          dryRun,
        }),
      );
    } catch (err) {
      setApplyError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <Card.Header
          title="Apply a proposal"
          subtitle="Opens a GitHub issue or pull request via integration-service."
        />
        <Card.Body className="space-y-4">
          <label className="block space-y-1">
            <span className="text-[11px] uppercase tracking-wider text-muted">Proposal</span>
            <select
              value={proposalKey(selected)}
              onChange={(e) => setSelectedKey(e.target.value)}
              className="w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
            >
              {proposals.map((p) => (
                <option key={proposalKey(p)} value={proposalKey(p)}>
                  {p.package.name} {p.from} → {p.to}
                  {p.status === 'manual_review' ? ' (manual review)' : ''}
                </option>
              ))}
            </select>
          </label>

          <label className="block space-y-1">
            <span className="text-[11px] uppercase tracking-wider text-muted">Integration ID</span>
            <input
              value={effectiveIntegrationId}
              onChange={(e) => setIntegrationId(e.target.value)}
              placeholder={integrationsLoading ? 'resolving…' : 'int-…'}
              className="aion-mono w-full rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text"
            />
          </label>

          <label className="flex items-center gap-2 text-sm text-text">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
            Dry run — render what would open, open nothing
          </label>

          <Button
            variant="primary"
            onClick={submit}
            disabled={submitting || !effectiveIntegrationId}
          >
            <GitPullRequest className="h-4 w-4" />
            {submitting ? 'Applying…' : dryRun ? 'Dry run' : 'Apply'}
          </Button>
        </Card.Body>
      </Card>

      {submitting && <LoadingCard label="Submitting to the agent…" />}
      {applyError && <ErrorCard message={applyError} />}
      {applyResult && (
        <Card>
          <Card.Header
            title={applyResult.applied ? 'Applied' : 'Not applied'}
            subtitle={
              applyResult.kind
                ? `${titleCase(applyResult.kind.replace('_', ' '))}${
                    applyResult.number ? ` #${applyResult.number}` : ''
                  } · ${applyResult.integrationId}`
                : applyResult.integrationId
            }
          />
          <Card.Body className="text-sm">
            {applyResult.url ? (
              <a
                href={applyResult.url}
                target="_blank"
                rel="noreferrer"
                className="aion-mono inline-flex items-center gap-1 text-accent hover:underline"
              >
                {applyResult.url}
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            ) : (
              <div className="text-muted">{applyResult.message}</div>
            )}
          </Card.Body>
        </Card>
      )}
    </div>
  );
}
