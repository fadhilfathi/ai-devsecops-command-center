# GitHub Integration Workflow

> **Document Owner:** SecurityArchitect
> **Sprint:** 1 (Foundation)
> **Status:** Approved for implementation
> **Classification:** Internal — Engineering
> **Last Updated:** 2026-06-12
> **Related Docs:** [system-architecture.md](./system-architecture.md), [security-model.md](./security-model.md), [event-bus.md](./event-bus.md)

---

## 1. Purpose & Scope

This document defines how the AI-DevSecOps Command Center integrates with **GitHub** to provide:

- **Per-repository security posture** (vulnerability, SBOM, secrets, IaC).
- **Pull Request automation** — pre-merge scanning, inline review comments, status checks.
- **Continuous monitoring** of default and feature branches.
- **Bidirectional sync** of issues, alerts, and remediation suggestions.

The integration is implemented as a **GitHub App** (preferred over OAuth Apps and PATs for security and scaling reasons) and lives primarily in the **Integration Service** with assistance from the **Security Service** (scanning) and **Agent Service** (remediation).

**In scope:** GitHub.com (primary). GitHub Enterprise Server (GHES) is supported via a self-hosted runner pattern described in §10.

**Out of scope:** GitLab, Bitbucket, Azure DevOps — separate integrations with their own design documents.

---

## 2. Why a GitHub App (not OAuth or PAT)

| Property | GitHub App | OAuth App | Personal Access Token |
|----------|------------|-----------|-----------------------|
| Per-installation identity | ✅ | ❌ | ❌ |
| Fine-grained permissions | ✅ | ⚠️ | ⚠️ |
| Short-lived tokens | ✅ (10 min) | ⚠️ | ❌ |
| Webhook events by installation | ✅ | ❌ | ❌ |
| Works for orgs without owning user | ✅ | ❌ | ❌ |
| Independent of user lifecycle | ✅ | ❌ | ❌ |

We standardize on **GitHub Apps** for all first-party integrations. PATs are only used as a last-resort fallback for tenants that cannot install Apps.

---

## 3. App Configuration

### 3.1 App Manifest

```json
{
  "name": "AI-DevSecOps Command Center",
  "url": "https://app.command-center.example",
  "hook_attributes": {
    "url": "https://api.command-center.example/github/webhook",
    "active": true,
    "events": [
      "pull_request",
      "push",
      "check_run",
      "check_suite",
      "issues",
      "issue_comment",
      "repository",
      "installation",
      "installation_repositories",
      "security_advisory",
      "dependabot_alert",
      "secret_scanning_alert",
      "code_scanning_alert"
    ]
  },
  "default_permissions": {
    "contents": "read",
    "metadata": "read",
    "pull_requests": "write",
    "checks": "write",
    "issues": "write",
    "statuses": "write",
    "actions": "read",
    "security_events": "read",
    "secret_scanning_alerts": "read",
    "vulnerability_alerts": "read",
    "dependabot_secrets": "read",
    "members": "read",
    "emails": "read"
  },
  "default_events": [
    "pull_request", "push", "installation"
  ]
}
```

### 3.2 Permissions — Justification

| Permission | Why needed |
|------------|------------|
| `contents:read` | Clone repos, read manifests (package.json, requirements.txt, etc.) |
| `metadata:read` | Basic repo info, required by GitHub |
| `pull_requests:write` | Post review comments, request changes |
| `checks:write` | Create Check Runs / Check Suites (status checks) |
| `issues:write` | File remediation issues, link findings |
| `statuses:write` | Update commit status (older API; fallback to checks) |
| `actions:read` | Read workflow run results, integrate with CI signals |
| `security_events:read` | Read code-scanning, secret-scanning, Dependabot alerts |
| `secret_scanning_alerts:read` | Pull alerts from GHAS |
| `vulnerability_alerts:read` | Receive Dependabot vulnerability webhooks |
| `dependabot_secrets:read` | Read Dependabot config for coordination |
| `members:read` | Map GitHub users → tenant users for attribution |
| `emails:read` | Resolve user emails for notification (where permitted) |

**No write access to `contents`** — we never push code; remediation goes through PRs authored by users or via the dedicated bot identity (see §3.4).

### 3.3 Webhook URL

- **Production:** `https://api.command-center.example/github/webhook`
- TLS terminated at the API gateway; webhook ingress is rate-limited and signature-verified.
- A separate **secondary URL** is configured for red/canary in multi-region deployments.

### 3.4 Bot Identity (for remediation PRs)

When the system needs to **open a PR** (e.g., auto-applied dependency upgrade), it uses a **secondary, dedicated GitHub identity** — either:

- A `command-center-bot` machine user (for tenants that prefer it), or
- The GitHub App's own identity (via installation token), where the tenant allows it.

The bot identity is **distinct from the App's installation token** so that tenants can grant/deny PR authorship independently from installation.

---

## 4. Installation Flow

### 4.1 User-Initiated Install

```
┌────────┐    ┌──────────┐    ┌────────┐    ┌──────────┐    ┌──────────┐
│ Owner  │ 1  │Command   │ 2  │ GitHub │ 3  │  GitHub  │ 4  │Command   │
│        │───►│ Center   │───►│ Install│───►│ Redirect │───►│ Center   │
│        │    │ UI       │    │ URL    │    │ +state   │    │ /callback│
└────────┘    └──────────┘    └────────┘    └──────────┘    └────┬─────┘
                                                                   │ 5
                                                                   ▼
                                                          ┌────────────────┐
                                                          │ Store install  │
                                                          │ + repos, issue │
                                                          │ setup webhook  │
                                                          └────────────────┘
```

### 4.2 State Validation

- A **CSPRNG state** parameter is generated per install attempt and stored (5-minute TTL).
- On callback, state is verified; mismatch aborts with 400.
- Prevents CSRF against the install flow.

### 4.3 What Happens on Install

1. Receive `installation` event from GitHub.
2. Verify HMAC-SHA-256 signature on the payload (see §8).
3. Resolve the installation to a tenant:
   - If the installing user already has a tenant → link.
   - Otherwise → create a new tenant and mark the installer as `owner`.
4. Persist:
   - `installation_id`
   - `account` (org or user)
   - `permissions` actually granted
   - `events` actually subscribed
   - `repositories_selection` (all / selected)
   - `repository_ids` if selected
5. For each selected repository: create an **Asset** record (see §5.1).
6. Dispatch a `github.install.completed` event to the event bus for downstream welcome workflow.
7. Send a welcome message to the installer's email and an audit log entry.

### 4.4 Repository Selection Changes

The `installation_repositories` event fires when a user adds/removes repos. The Integration Service:

- **Adds:** create Asset, schedule initial scan.
- **Removes:** mark Asset as `archived`, stop scheduling, retain historical findings for compliance.

### 4.5 Suspension & Deletion

| GitHub event | Action |
|--------------|--------|
| `installation.suspended` | Pause all scheduled work; keep last state; mark tenant `integration_paused` |
| `installation.unsuspended` | Resume scheduling |
| `installation.deleted` | Mark tenant `integration_removed`; retain audit data per retention policy; revoke installation token |

---

## 5. Repository & Asset Model

### 5.1 Asset (Repository) Record

```yaml
asset:
  id: uuid
  tenant_id: uuid
  integration_id: uuid        # points to the GitHub installation
  external_id: 123456         # GitHub repo id
  full_name: acme/widget-api   # org/repo
  default_branch: main
  visibility: private|public|internal
  languages: [typescript, python]
  topics: [api, payments]
  status: active|paused|archived
  policies:
    pr_scan: enabled
    scheduled_scan: daily
    block_on_critical: true
    block_on_high: false
    sast: enabled
    sca: enabled
    secrets: enabled
    iac: enabled
    container: enabled
    sbom: enabled
  first_seen_at: ts
  last_scanned_at: ts
  last_commit_sha: sha
```

### 5.2 Repository Configuration File

Tenants can commit a `command-center.yml` (or `.github/command-center.yml`) to override defaults per-repo:

```yaml
version: 1
policies:
  block_on:
    - severity: critical
    - severity: high
      cwe: [79, 89, 22]   # only block on these CWEs at high
  ignore:
    - path: "**/test/**"
    - rule: "GHA-BADGE-001"
      reason: "Test fixture; tracked in JIRA-1234"
      expires: 2026-12-31
  scan_schedule:
    full: weekly
    incremental: on_push
  notify:
    channel: "#security-alerts"
    on:
      - new_critical
      - new_high_in_main
  auto_remediate:
    dependencies: true
    secrets: false
    code: suggestion_only
```

The file is **fetched on every PR scan** (cached for ≤60s) and re-fetched when the file changes on the default branch.

---

## 6. PR Scanning Workflow

### 6.1 End-to-End Flow

```
  PR opened / synchronized
        │
        ▼
  GitHub sends pull_request webhook
        │
        ▼
  Integration Service receives + verifies signature
        │
        ▼
  Persist event (idempotency by delivery id)
        │
        ▼
  Emit event: github.pr.scan_requested
  { tenant_id, installation_id, repo, pr_number, head_sha, base_sha, commit_message }
        │
        ▼
  Scan Orchestrator consumes event
        │
        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                  Parallel scan pipeline                     │
  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ │
  │  │  SAST   │ │  SCA    │ │ Secrets │ │   IaC   │ │  SBOM  │ │
  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───┬────┘ │
  │       └──────────┴───────────┴────────────┘          │      │
  │                              ▼                         │      │
  │              Findings Aggregator (dedupe, enrich)     │      │
  │                              │                         │      │
  │              Publish github.scan.completed             │      │
  └──────────────────────────────┬────────────────────────┘      │
                                  │                              │
                                  ▼                              │
  Result Reporter consumes github.scan.completed                  │
  │  - Create / update Check Run                                 │
  │  - Post / update PR review comments                          │
  │  - Attach SBOM as workflow artifact ◄────────────────────────┘
  │  - If block policy triggers: dismiss previous approval
  │  - If pass: clear blocking check
  ▼
  GitHub UI shows status, comments, SBOM artifact
```

### 6.2 Check Run Lifecycle

- **Name:** `command-center/security`
- **Status:** `queued` → `in_progress` → (`completed`)
- **Conclusion:** `success` | `failure` | `neutral` | `cancelled` | `action_required` | `timed_out`
- **Conclusion logic:**
  - `failure` — block policy triggered (e.g., critical CVE, hardcoded secret).
  - `action_required` — high severity not blocking, but reviewer attention requested.
  - `success` — clean or only findings under threshold.
  - `neutral` — scan completed but no findings.
- **Required check:** repositories can mark `command-center/security` as a required status check; our block policy directly translates to merge blocking.

### 6.3 Inline PR Comments

We post **up to one comment per file/line combination** (deduplicated) to avoid spamming PRs:

- Comments include: finding ID, severity, CWE, OWASP category, description, remediation guidance, and a link to the full report in the Command Center.
- Comments are **grouped into a single review** with a dismissable "stale" status.
- If findings become outdated (code changes), comments are marked `outdated` and dimmed; never deleted (preserves history).
- **Suggested changes** (for code and IaC) are posted as GitHub **suggestion blocks** for one-click commit.

### 6.4 SBOM Attachment

After every PR scan and every release tag, a **CycloneDX SBOM** is generated and attached as a **GitHub Actions workflow artifact** in the **Check Run** output:

- Format: `application/vnd.cyclonedx+json` and `application/vnd.cyclonedx+xml`.
- Files included: all source files, dependencies, container images (if Dockerfile detected).
- Signed with the Integration Service's PGP key; signature also attached.
- A **direct URL** in the Check Run summary points to the SBOM in the Command Center for full provenance.

### 6.5 Pull Request Dismissals on Policy Violation

When a new commit introduces a finding that **triggers the block policy**:

- The previous `success` Check Run is **re-requested** (new run for the new SHA).
- The old `success` is not manually overridden — GitHub treats the new run as authoritative for the latest SHA.
- If the repo has branch protection requiring the check, the PR is automatically blocked from merge.

---

## 7. Status Checks & Branch Protection

### 7.1 What We Publish

| Check | Source | When |
|-------|--------|------|
| `command-center/security` | PR scan (this doc) | Every PR open/sync |
| `command-center/sbom` | SBOM generation | Every PR + every release |
| `command-center/dependency-review` | Dependency diff vs base | Every PR (incremental) |
| `command-center/policy` | Policy gate (block logic) | After scan completes |

### 7.2 Recommended Branch Protection

We recommend (and document in tenant onboarding):

- ✅ Require `command-center/security` to pass before merge.
- ✅ Require branches to be up to date before merge.
- ✅ Require review from CODEOWNERS (security team for security-sensitive paths).
- ✅ Dismiss stale pull request approvals when new commits are pushed.
- ✅ Restrict who can push to protected branches.

### 7.3 Required Check Installation

- On install, we offer a **"configure branch protection"** one-click action that:
  - Lists the repos where the App has admin permission.
  - For each, applies a recommended branch protection rule (idempotent, additive).
  - Records a `policy.applied` audit event.

---

## 8. Webhook Ingestion

### 8.1 Signature Verification

Every inbound webhook is verified before processing:

```
expected = "sha256=" + HMAC_SHA256(GITHUB_APP_WEBHOOK_SECRET, raw_body)
received = header["X-Hub-Signature-256"]
if !constant_time_equals(expected, received):
    respond 401 + emit security.webhook.signature_failed
```

`raw_body` must be captured **before** any JSON parsing. Verification must use a constant-time compare.

### 8.2 Idempotency

- GitHub may redeliver a webhook (network blip, app restart).
- Every event has an `X-GitHub-Delivery` GUID.
- We **dedupe by (delivery_id, event_type, installation_id)** for 24 hours.
- Duplicate deliveries are **ack'd 200** but skipped.

### 8.3 Replay Protection

- Each delivery is timestamped by GitHub (`X-GitHub-Hook-Installation-Target-ID` + body timestamp).
- Reject deliveries with `> 5 minute` clock skew.

### 8.4 Webhook Event Handling

| Event | Handler | Action |
|-------|---------|--------|
| `installation` | install/suspend/unsuspend/delete | Tenant & asset state updates |
| `installation_repositories` | repos added/removed | Asset create/archive |
| `pull_request` | opened/synchronize/reopened | Trigger scan |
| `pull_request` | closed/merged | Final scan, close out alerts |
| `push` | new commits on watched branch | Incremental scan |
| `check_run` | rerequested | Re-run scan for that SHA |
| `check_run` | completed (from CI) | Correlate with scan result |
| `issues` | opened/labeled | Link to vulnerability/incident |
| `issue_comment` | new comment | Bidirectional reply sync |
| `secret_scanning_alert` | created/resolved | Mirror as finding |
| `dependabot_alert` | created/resolved | Mirror as vulnerability |
| `code_scanning_alert` | created/resolved | Mirror as finding |
| `repository` | renamed/archived/transfered | Update asset, pause on archive |
| `member` | added/removed | Tenant membership update |
| `ping` | test | Acknowledge |

### 8.5 Rate Limit Awareness

- GitHub webhooks are not rate-limited, **but** our processing is.
- The Integration Service uses a **bounded consumer** with backpressure: if downstream is overloaded, we accept the webhook (200), queue it in Redis Streams, and process asynchronously.
- We honor GitHub's `Retry-After` and exponential backoff hints when calling the GitHub API.

---

## 9. Outbound GitHub API Usage

### 9.1 Token Strategy

- All outbound calls use an **installation access token** obtained from GitHub:
  ```
  POST https://api.github.com/app/installations/{installation_id}/access_tokens
  Authorization: Bearer <app_jwt>
  ```
- Tokens are **10-hour JWTs** signed with the App's private key; cached in Redis with a 5-minute pre-expiry refresh.
- The App's private key is stored in **Vault**; never on disk.

### 9.2 GraphQL vs REST

| Use case | API | Why |
|----------|-----|-----|
| Listing PRs, files | GraphQL | Fewer round-trips, less rate-limit burn |
| Creating Check Runs | REST | More mature for check management |
| Posting review comments | GraphQL (PR review thread API) | Stable since 2022 |
| Reading alerts | GraphQL | Unified across secret/dependabot/code-scanning |
| Repository metadata | REST | Simpler for ad-hoc lookups |

### 9.3 Rate Limit Budgeting

- GitHub's primary rate limit: **5000 req/h per installation**.
- We budget per-installation:
  - 60% for scan-driven traffic
  - 20% for webhook-driven (status updates, comment updates)
  - 15% for housekeeping (branch protection, repo metadata refresh)
  - 5% reserve for ad-hoc
- We monitor remaining quota and **shed load** (queue, not drop) when below 10%.

### 9.4 Conditional Requests

- Use `If-None-Match` ETags and `If-Modified-Since` for read calls that can change between checks.
- Reduces GitHub rate-limit burn by ~30% in steady state.

---

## 10. GitHub Enterprise Server (GHES) Support

For tenants running GHES:

- A **GitHub App** can be installed on GHES 3.4+ with the same permissions.
- Webhook URL points to the customer's reachable endpoint (or a relay through the customer's gateway).
- API base URL is **configurable per integration** (`https://github.<tenant>.example/api/v3`).
- For on-prem scan execution, a **self-hosted runner** is registered with the Command Center; it pulls scan jobs over a single outbound HTTPS connection (no inbound firewall changes required).
- All security and audit controls are identical to github.com; no degraded mode.

---

## 11. Secrets & SBOM in Repositories

### 11.1 Secret Scanning Findings

When a secret is detected (by us or by GitHub):

1. Finding is created with `severity = critical`, `type = secret`, `class = <provider>` (e.g., `aws-access-key`).
2. PR check is **failed** (block policy).
3. Inline PR comment is posted **without revealing the secret value** (a partial fingerprint only).
4. A remediation issue is opened with rotation instructions and a `rotation_due` date.
5. The original token is **not** sent to Command Center logs; only its hash and provider class are stored.
6. A "secret never stored in our DB" guarantee is in our public trust page.

### 11.2 SBOM Generation

- Triggered on:
  - PR open/sync (the changed snapshot)
  - Tag push matching `v*` (full release)
  - Manual request via API or UI
- Generators (per ecosystem):
  - npm/yarn/pnpm → `cdxgen`
  - pip/poetry → `cdxgen` or `syft`
  - Maven/Gradle → `syft` or `cyclonedx-maven-plugin`
  - Go → `syft`
  - Cargo → `cargo-cyclonedx`
  - Docker images → `syft <image>`
  - Mixed → `syft` as fallback
- Output is signed (cosign keyless or HMAC for non-container artifacts) and published to the Command Center.
- A **signed SBOM URL** is also attached to GitHub release pages via the Checks API.

---

## 12. Remediation Workflows

### 12.1 Dependency Upgrades

- For SCA findings with a known fix version, the **Remediation Agent** proposes a PR using the `command-center-bot` identity.
- PR body includes: list of changes, expected resolution of findings, test plan, risk score.
- **Auto-merge** is **never** enabled by default; auto-merge is opt-in per repo and per ecosystem.
- For high-risk upgrades (e.g., major version bumps), the agent **requests a human reviewer** explicitly.

### 12.2 Code Fix Suggestions

- For SAST findings, the agent posts a **GitHub suggestion block** (the small "Apply suggestion" button).
- Suggestions are **advisory only** — never auto-committed.
- A `command-center.remediation.applied` audit event fires when a human accepts a suggestion.

### 12.3 Issue Synchronization

- Each vulnerability and incident can be **linked** to a GitHub issue (one-to-one).
- Issue title, labels, and body are kept in sync (state transitions mirrored both ways).
- Closing the issue in GitHub → marks the finding `resolved` in the Command Center (with an audit trail).
- Comment sync: GitHub issue comments ↔ Command Center incident comments.

---

## 13. Permissions Model (Tenant-Side)

| Action | GitHub Permission | Why |
|--------|-------------------|-----|
| Clone repo | `contents:read` | Scan engine input |
| Post review | `pull_requests:write` | Inline comments |
| Create Check Run | `checks:write` | Status reporting |
| Create issue | `issues:write` | Remediation issues |
| Set status | `statuses:write` | Fallback for older check API |
| Read alerts | `security_events:read`, `secret_scanning_alerts:read`, etc. | Mirror GHAS findings |
| Modify branch protection | **NOT requested** | We don't auto-modify repo settings without explicit user action |
| Read members | `members:read` | User attribution |
| Push code | **NOT requested** | Remediation uses a separate bot identity with its own auth, not the App |

The App **never** requests `contents:write` on the App itself; all code writes happen via the separate `command-center-bot` machine user or via user-authored commits.

---

## 14. Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Webhook signature invalid | Counter spike | Alert, quarantine source IP for 1h, log |
| Webhook backlog growing | Queue depth | Auto-scale workers; alert at 5 min SLO breach |
| GitHub rate limit exhausted | API 403 with `X-RateLimit-Remaining=0` | Queue outbound calls, retry after reset, notify tenant at 80% |
| Installation token expired | API 401 | Auto-refresh from Vault before next call |
| GHES unreachable | Health check | Pause integration, mark `degraded`, alert tenant admin |
| App private key rotation | Scheduled | New key in Vault; old key valid for 7-day overlap; update GitHub App setting; restart pods |
| Bot identity loses access | API 401/403 on PR create | Fall back to suggestion-only mode; alert security admin |

---

## 15. Observability

### 15.1 Metrics (Prometheus)

- `github_webhook_received_total{event, tenant_id, result}`
- `github_webhook_processing_duration_seconds{event, quantile}`
- `github_api_requests_total{endpoint, status}`
- `github_api_remaining_quota{installation_id}`
- `github_check_run_duration_seconds{conclusion}`
- `github_pr_findings_total{severity, type}`
- `github_remediation_prs_total{ecosystem, result}`

### 15.2 Logs

- Structured JSON; fields: `tenant_id`, `installation_id`, `repo`, `pr_number`, `delivery_id`, `trace_id`, `actor`.
- **Redaction:** never log secrets, full SBOM content, or raw webhook bodies (only headers + event name + delivery id).
- Log retention: 30 days hot, 1 year warm (see SRE logging spec).

### 15.3 Tracing

- W3C `traceparent` generated at webhook ingress.
- Spans cover: webhook receive → enqueue → consume → scan → check run → comment → respond.
- Sampling: 100% for errors, 10% for successes.

---

## 16. Security Considerations

This section highlights security-specific aspects of the integration. The full security model is in [security-model.md](./security-model.md); key integration-specific items:

| Concern | Control |
|---------|---------|
| **Webhook spoofing** | HMAC-SHA-256 signature verification, constant-time compare |
| **Replay attacks** | Delivery-id dedupe (24h) + clock skew check |
| **Token theft** | Installation tokens cached in Redis only, TTL 9h, refreshed in memory |
| **Excessive permissions** | Principle of least privilege in App manifest; per-installation permission audit weekly |
| **Tenant data leakage** | Every outbound call scoped to the installation's `tenant_id`; `repository_ids` enforced |
| **Abuse of PR commenting** | Per-PR comment budget (≤20 per scan); comment deduplication |
| **Compromised bot identity** | Bot cannot read secrets or merge PRs; PRs require human review |
| **App private key compromise** | Vault-managed, rotated quarterly, alarm on retrieval; keys never logged |
| **GHES-specific risks** | Per-tenant network segmentation; no shared outbound proxy |

### 16.1 Threat Scenarios (Integration-Specific)

- **Scenario:** Attacker compromises a user's GitHub account that has the App installed.
  - **Impact:** Attacker can push code that the App will scan, view past comments, but **cannot** impersonate the App, create new installations, or change App-level settings.
  - **Mitigation:** Token lifetime is short; scoped permissions; user can revoke in GitHub settings.
  - **Detection:** Anomalous user activity from outside tenant's normal IP/geo range.

- **Scenario:** Attacker submits a malicious PR with a payload that exploits our comment renderer.
  - **Mitigation:** All comment content is sanitized; suggestions are diff-validated before posting; GitHub's own renderer is the second line of defense.
  - **Detection:** Output encoding regression tests in CI.

- **Scenario:** Attacker sends a forged webhook to `/github/webhook`.
  - **Mitigation:** Signature verification (mandatory). No fallback to "trusted IP" — IP is not a secret.
  - **Detection:** Signature failure counter spikes.

---

## 17. Implementation Checklist

The Integration Service team must complete, in order, before public release:

- [ ] GitHub App registered, manifest published
- [ ] Webhook receiver with signature verification
- [ ] Idempotency store
- [ ] Installation lifecycle handlers
- [ ] Asset model & repository config parser
- [ ] PR scan orchestrator
- [ ] SAST, SCA, Secrets, IaC, SBOM scanner integrations
- [ ] Check Run reporter
- [ ] Inline comment reporter
- [ ] Branch protection recommendation engine
- [ ] Remediation PR creator (bot identity)
- [ ] GHES support (configurable API base, self-hosted runner)
- [ ] Rate limit budget + shedding
- [ ] Metrics, logs, traces per §15
- [ ] Pen-test of the integration before GA
- [ ] Documentation for tenants and admins
- [ ] Runbook for on-call

---

## 18. Open Questions / Future Work

| Topic | Owner | Status |
|-------|-------|--------|
| GitHub Enterprise Cloud (EMU) support | SecurityArchitect + GitOps | To scope |
| Real-time PR comment streaming (via GraphQL Subscriptions) | Integration team | Research |
| Auto-fix for IaC findings (terraform) | Agent team | Roadmap |
| Native Dependabot config generator | Agent team | Roadmap |
| Custom rule packs per tenant | Security team | Design in Q3 |
| Audit log export to GHES Audit Log API | SRE | To scope |

---

## 19. References

- GitHub Apps documentation — https://docs.github.com/en/apps
- GitHub Webhook events and payloads — https://docs.github.com/en/webhooks
- CycloneDX Specification 1.5 — https://cyclonedx.org/spec
- NIST SSDF (SP 800-218) — Secure Software Development Framework
- OWASP Top 10 for CI/CD (2024)
- OWASP SAMM v2 — Software Assurance Maturity Model

---

*End of GitHub Integration Workflow.*
