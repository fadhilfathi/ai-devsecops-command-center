# Sprint 11 — Cluster delete, remediation follow-through, remediation UI, security persistence

Sprint 11 closed the remediation loop end to end — the proposals S10-1
started producing can now become real GitHub issues/PRs and are visible
in the UI — and picked up the two remaining persistence/API debts:
cluster CRUD (so S10-4's cache eviction has a real trigger) and
Postgres backing for security-service.

## Cluster CRUD and SSRF guard (S11-1)

`kubernetes-service` gained `POST /v1/kubernetes/clusters`,
`PATCH /v1/kubernetes/clusters/:id`, and
`DELETE /v1/kubernetes/clusters/:id` — all `platform_admin`-only,
tenant-scoped, and responses never include `token`/`caBundle`. `DELETE`
and credential rotation call the new `LiveProvider.evict()` (via
`ProviderRegistry.evictLive()`), so the S10-4 cache-eviction path is
exercised by a real API call instead of only by `clientsFor`'s
per-call existence check.

Onboarding a cluster now runs its `server` URL through a new SSRF guard
(`src/ssrf-guard.ts`): https-only, link-local/cloud-metadata addresses
(169.254.0.0/16, `fd00:ec2::254`) always rejected, RFC1918/unique-local
private ranges allowed by default (on-prem is the common case), loopback
rejected unless `AICC_K8S_ALLOW_PRIVATE_API=true`. Hostname literals are
additionally resolved and every returned address classified the same way
(`checkServerUrlDns`), failing closed on resolution errors — checked at
create/test-connection time and again right before each connect. The old
`POST /v1/kubernetes/test-connection` SSRF oracle (arbitrary
caller-supplied `server`, no auth, raw error text echoed back) is closed:
`platform_admin` only, guard runs before dialling out, provider error
text never echoed. See `CHANGELOG.md`'s Security section.

## remediation.apply → GitHub issues/PRs (S11-2)

S10-1's `remediation.apply` returned `applied: false` unconditionally —
the agent never opened anything. It now goes through
integration-service's new `POST /v1/integrations/:integrationId/remediation`
to open a real issue or PR:

- `agent-service`'s `applyRemediation()` keeps the policy gates and
  injects the HTTP hop (`deps.callIntegration`, wired to the new
  `createIntegrationClient` in `backend/services/agent/src/
  clients/integration.client.ts`, which mints a 60s internal token per
  call). A missing `integrationId`, or a proposal with `status !== 'ok'`
  (`manual_review` needs human approval), returns `applied: false`
  without any network call; integration-service errors propagate so the
  task fails loudly.
- `integration-service` resolves the tenant's GitHub integration
  (unknown, disabled, and foreign-tenant ids all 404), requires a
  `github` provider (409) with `owner`/`repo` and a token in `config`
  (422), and calls GitHub through the new `GithubClient`
  (`src/providers/github.client.ts`) — bearer auth with the
  user-supplied PAT (`config.token`/`config.pat`, decrypted at use via
  the ADR-0016 `AICC_CREDENTIAL_KEYS` keyring), `GITHUB_API_URL`
  overridable for GHES, 10s timeout, injectable `fetchImpl`.
- `selectRemediationTarget` decides issue vs pull request: a PR only for
  an `ok` proposal whose `context.repo` names an explicit
  `owner/repo#branch`, everything else an issue (the platform never
  pushes code — a PR can only reference a branch that already exists).
  `renderRemediationBody` produces deterministic markdown (no LLM), and
  `dryRun` returns the target with zero outbound calls.
- GitHub failures map to a generic 502 (`UPSTREAM_FAILURE`) carrying no
  upstream body text — `GithubApiError` keeps the status only, which is
  what gets logged. Every attempt records a `github.remediation` sync
  row and publishes `integration.sync.completed`.

See [ADR 0021](../../adr/0021-outbound-github-remediation.md).

## Triage/remediation screen (S11-3)

S9-4/S10-1 shipped the agents' output backend-only; the new
`/remediation` page (`frontend/src/routes/Remediation.tsx`, lazy route +
sidebar entry) surfaces it in three URL-addressable tabs
(`?view=triage|proposals|apply`): Triage (per-finding scores and
rationale from `triage.findings`), Proposals (dependency bumps with
risk level, `manifestHint`, `manual_review`/`unresolved` fallbacks from
`remediation.propose`), and Apply (submit one proposal via
`remediation.apply`, with an integration picker and dry run on by
default).

- The run action maps the current vulnerability rows through
  `toAgentFinding`; `postAgentTask` (`src/lib/api.ts`) submits an agent
  task and polls it (500 ms × ≤20 — bounded, throws on failure or
  timeout, and never substitutes mock data for a live failure).
- `frontend/src/types/index.ts` gains the agent-service wire types
  (`TriageFinding`, `TriageResult`, `RemediationProposal`,
  `RemediationResult`, `ApplyInput`, `ApplyResult`, the task envelope)
  mirroring `backend/services/agent/src/agents/{triage,remediation}.ts`
  exactly — no frontend-only reshaping.
- `deriveEcosystem()` covers the one gap in the `Vulnerability` wire
  type (no ecosystem field): inferred from the package name (scoped →
  npm, slash path → go, `group:artifact` → maven, PascalCase → nuget,
  `.`/`_` → pypi, else npm). Scoring fields that genuinely aren't
  derivable (KEV, EPSS, exposure, asset criticality) stay unset rather
  than invented. Mocks (`mockTriageResult`, `mockRemediationResult`,
  `mockApplyResult`) serve the default `VITE_USE_MOCKS` path; tests in
  `frontend/src/App.remediation.test.ts`.

## security-service Postgres persistence (S11-4)

`security-service`'s `AssetRepository`, `ScanRepository`,
`FindingRepository`, and `SbomRepository` (including the S10-2
component/edge index) got `buildPg<X>Repository` implementations
mirroring the in-memory ones (tenant scoping, filters, ordering), tested
with `describe.each` against `@electric-sql/pglite`. `DATABASE_URL`
switches security-service onto Postgres at startup with a `/readyz` DB
check; unset stays in-memory (tests, `pnpm dev`). The index rebuild
(`SbomRepository.replaceComponents`' delete + bulk insert across two
tables) runs atomically via a new `withTransaction()` helper in
`@aicc/shared/db`. Pre-existing gap, deliberately mirrored rather than
fixed out-of-band: `ScanRepository.updateStatus(id, status)` has no
`tenantId` parameter, so it is not tenant-scoped in either
implementation. See the S11-4 note in
[ADR 0010](../../adr/0010-postgres-persistence.md).

## How to run it

Unchanged from Sprint 10:

```bash
pnpm install
pnpm --filter @aicc/security-service dev   # etc., per service
cd frontend && pnpm dev                     # mocks on by default
```

or the full containerised stack:

```bash
docker compose up --build
node scripts/e2e-smoke.mjs
```

`remediation.apply` additionally needs a GitHub integration with
`owner`/`repo` and a PAT in its `config`, and agent-service needs
`INTEGRATION_SERVICE_URL` (defaults to `http://127.0.0.1:3006`; the
compose stack sets it).

## Manual steps for the maintainer

Unchanged from Sprint 7/8/9/10 — neither has been applied yet:

- Apply the branch protection checklist in
  [`docs/operations/branch-protection.md`](../../operations/branch-protection.md)
  under Settings → Branches.
- Enable GitHub's private vulnerability reporting (Settings →
  Security → Reporting).

## Still deferred

- The GitHub App integration (`github-integration.md`) — installation
  tokens, bot identity, bidirectional issue sync. ADR 0021 documents the
  user-supplied PAT as the local-first implementation.
- Encrypt-on-write for the integration `config` token (the read path
  already decrypts ADR-0016 ciphertexts; `POST /v1/integrations` stores
  `config` as supplied). See ADR 0021's note.
- The remaining in-memory-only services (auth, agent, compliance,
  integration, k8s-health, runtime-security, inventory,
  cost-intelligence, topology, reporting).
- PyJWT 2.15 PRs (#69/#70) — still open.
- The maintainer manual steps above (branch protection, private
  vulnerability reporting).

## Next steps (Sprint 12)

Release 1.0 readiness. See `ROADMAP.md`.
