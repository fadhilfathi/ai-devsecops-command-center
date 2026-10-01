# 0021 — Outbound GitHub remediation with a user-supplied PAT

Status: accepted
Date: 2026-10-01

## Context

S10-1 made `RemediationAgent` propose real dependency bumps, but
`remediation.apply` deliberately returned `{ applied: false }` — the
agent only suggested, it never touched a repository. Sprint 11 closes
the loop: apply a proposal by opening a GitHub issue or pull request
carrying the proposal's `manifestHint`.

`docs/architecture/github-integration.md` (Sprint 1) sketched the
"proper" integration — a GitHub App with installation tokens, a bot
identity, webhook dedupe, and App private keys in Vault. That design
assumes hosted infrastructure this project does not run: the zero-cost
rule (`CLAUDE.md`) forbids paid APIs, cloud accounts, and SaaS trials,
and everything must run locally or on free GitHub Actions. The need
here is much narrower than that design: one-way, on-demand "open an
issue or PR in the tenant's repo" writes.

## Decision

- **A user-supplied personal access token, not a GitHub App.** Each
  GitHub integration carries its own fine-grained PAT in the
  `integrations` row's `config` (`token` or `pat`) — the credential
  shape integrations rows already store. A GitHub App would need app
  registration, a private key with per-installation JWT/token exchange,
  and webhook plumbing (the old design assumes Vault just for the key);
  a PAT needs none of that and costs nothing beyond a token the tenant
  already owns. The issue/PR is authored as the PAT's user — honest
  attribution, and the tenant scopes the token to the one target repo
  (`issues` and/or `contents`/`pull_requests` write). The GitHub App
  path in `github-integration.md` §2 remains the shape to move to if
  this is ever hosted; this ADR is the local-first implementation.

- **Where the credential lives and how it is protected at rest**: the
  tenant's `integrations` row, `config.token`/`config.pat`. At use time
  `resolveToken` (`routes/integrations.ts`) runs it through
  `@aicc/shared/crypto`'s `decryptSecret(parseKeyring(AICC_CREDENTIAL_KEYS),
raw, { allowPlaintext: true })` — the same AES-256-GCM envelope
  ciphertext format (`v1.<keyId>.<iv>.<tag>.<ct>`, key id as AAD) and
  keyring/rotation procedure as the cluster credentials in
  [ADR 0016](./0016-credential-encryption-at-rest.md). A stored value
  encrypted with `encryptSecret` under the `AICC_CREDENTIAL_KEYS` keyring
  is encrypted at rest and decrypted only for the outbound call;
  plaintext is passed through unchanged when no keyring is configured or
  the value is not ciphertext (the same dev/test tolerance as
  kubernetes-service's legacy plain columns). **Note:** the create path
  stores `config` exactly as supplied — there is no encrypt-on-write on
  `POST /v1/integrations` yet (unlike `cluster.repository.ts`), so
  storing the token as ciphertext is done before storage. Encrypting on
  write is a follow-up.

- **Issue vs pull request** (`selectRemediationTarget`, pure and
  unit-pinned): a pull request is attempted **only** when the proposal
  is clean (`status === 'ok'`) **and** the caller explicitly named a
  source branch via an `owner/repo#branch` suffix on `context.repo`;
  everything else — including `manual_review` proposals and a missing or
  empty branch — opens an issue. The platform never pushes code (the
  `manifestHint` stays a human-run command), so a PR can only ever point
  at a branch that already exists on GitHub; asking for one implicitly
  would just fail. And a `manual_review` proposal has not been approved
  by a human, so it must not be auto-applied — `applyRemediation()`
  (agent-service) refuses it before any network call, and the route
  would fall back to an issue even if called directly.

- **The issue/PR body is deterministic markdown**
  (`renderRemediationBody`): same proposal in, same text out — package,
  update range, bump class, risk, resolved findings, the `manifestHint`
  in a fenced block, and optional finding/CVE/asset/repo context. No
  LLM in the write path (zero-cost, and no prompt-injection surface on
  an outbound credential).

- **Dry run**: `dryRun: true` resolves and reports the target
  (`{ opened: false, dryRun: true, kind, message }`) and returns before
  a `GithubClient` is even constructed — zero outbound calls (pinned by
  a test that makes `fetch` throw). The remediation UI's Apply tab
  defaults to dry run, so the first click can never open anything by
  accident.

- **Errors are sanitised to a generic 502.** `GithubApiError` carries
  the response **status only**; GitHub's response body is never
  propagated. Those bodies can reveal repo existence, auth/token scope
  problems, and other upstream internals to a tenant user who should
  not see them (same reasoning as the S11-1 test-connection fix). The
  route logs the upstream status and target URL for operators and
  returns `UPSTREAM_FAILURE` (502) with a fixed message. The full local
  status contract before dialling out:
  - **404** — the integration id is unknown, disabled, or belongs to
    another tenant (deliberately indistinguishable);
  - **409** — the integration's provider is not `github`;
  - **422** — the github integration's `config` is missing `owner`/
    `repo`, or a token (`token`/`pat`);
  - **502** — GitHub failed (sanitised, as above).

- **Tenant and authorisation model.** Every lookup is tenant-scoped
  (`integrations.findById(id, tenantId)` against the verified JWT
  tenant, never a caller header), so one tenant can never apply through
  another tenant's integration. The route requires an authenticated
  tenant (`requireTenant`) — the same gate as the other integration
  routes. The agent-service → integration-service hop
  (`createIntegrationClient`, `backend/services/agent/src/
clients/integration.client.ts`) mints a 60-second HS256 internal
  token per call (`sub: 'system:agent-service'`,
  `role: 'platform_admin'`) and sends `x-tenant-id` — the same pattern
  as cost-intelligence/topology's inventory calls — and never surfaces
  an upstream response body to the agent caller either (bare status in
  the error). Every apply attempt — success or failure — records a
  `github.remediation` sync row and publishes
  `integration.sync.completed`, so applied remediations are auditable
  alongside webhook syncs.

- **`GITHUB_API_URL`** overrides the REST base URL (default
  `https://api.github.com`) for GitHub Enterprise Server; `GithubClient`
  takes it as `baseUrl`, uses native `fetch` with a 10s
  `AbortSignal.timeout`, and keeps `fetchImpl` injectable so the whole
  path tests offline.

## What this does NOT protect against

- **A compromised integration-service.** It holds `AICC_CREDENTIAL_KEYS`
  and the DB, so it can use any stored PAT — this defends credentials
  at rest (a leaked dump or backup), not a compromised running service.
- **PAT scope and lifecycle.** The tenant chooses the token's scopes and
  rotates it; a broad classic PAT works and is the tenant's risk. There
  is no config-update route (the only `PATCH` toggles `enabled`), so
  rotating a PAT means updating the stored `config` out-of-band or
  recreating the integration, and nothing detects an expired token
  before the 502.
- **Process memory.** The decrypted token is a plain string for the
  duration of the outbound call.

## Consequences

- `remediation.apply` is end-to-end real: proposal → validated apply →
  GitHub issue/PR URL back in the task result and the UI.
- GHES works with no code change (`GITHUB_API_URL`); the compose stack
  passes it through.
- Issues/PRs are authored as the PAT's user, not a bot identity — the
  `command-center-bot` machine user from `github-integration.md` §3.4
  stays deferred with the App.
- A PR apply fails if the named `#branch` does not exist on GitHub; the
  failure is the generic 502, and dry run is the discovery mechanism
  for the intended target.
- Zero-cost is preserved: no App, no paid API, no new dependency
  (native `fetch`, `@aicc/shared/crypto` from ADR 0016).
- Amends `docs/architecture/github-integration.md` §2's "GitHub App,
  PATs only as a last resort" stance for the local-first platform —
  see this ADR for what is actually implemented. Superseded by a future
  ADR if a hosted GitHub App integration ever lands.
