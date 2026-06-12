# Security automation runbook

> **Owner:** GitOpsManager
> **Workflows covered:**
> - [`.github/workflows/security.yml`](../.github/workflows/security.yml) — SBOM commit, vuln report, weekly digest, cleanup, SLA sync
> - [`.github/workflows/security-issue.yml`](../.github/workflows/security-issue.yml) — Critical CVE issue opener
> - [`.github/workflows/release.yml`](../.github/workflows/release.yml) (job `attach-sbom`) — SBOM release attachment
>
> **Folder contract:** [`security/README.md`](../security/README.md)

This runbook is the operator's reference for everything the security
automation does, how to triage its output, and how to override /
rollback when it misbehaves.

---

## Table of contents

1. [System map](#system-map)
2. [Triggers reference](#triggers-reference)
3. [Daily / weekly cadence](#daily--weekly-cadence)
4. [Operator workflows](#operator-workflows)
   - [Triage a Critical CVE issue](#triage-a-critical-cve-issue)
   - [Override a bot commit](#override-a-bot-commit)
   - [Manually trigger](#manually-trigger)
   - [Roll back a bot PR](#roll-back-a-bot-pr)
   - [Disable the workflows in an incident](#disable-the-workflows-in-an-incident)
   - [Run from a fork (security researcher flow)](#run-from-a-fork-security-researcher-flow)
5. [Common failure modes](#common-failure-modes)
6. [Debugging](#debugging)
7. [Contact](#contact)

---

## System map

```
                ┌──────────────────────────────────────────────────────┐
                │             EXTERNAL EVENT SOURCES                    │
                │   GitHub Security Advisories, OSV/NVD, Snyk, snyk.io  │
                └─────────────────────────┬────────────────────────────┘
                                          │
                                          ▼
                ┌──────────────────────────────────────────────────────┐
                │      vulnerability-intel service (port 4008)         │
                │  Ingests OSV/NVD/GHSA, normalises to NDJSON record,  │
                │  publishes to Redis Stream subject:                  │
                │      security.vulnerability.detected.v1              │
                └─────────────────────────┬────────────────────────────┘
                                          │
                                          ▼
                ┌──────────────────────────────────────────────────────┐
                │  github-bridge service (planned for S2.x)            │
                │  Consumes Redis Stream subject                       │
                │      `security.vulnerability.detected.v1`            │
                │  and projects the rich per-CVE `VulnerabilitySchema` │
                │  to the GitOps wire format (per-finding, see         │
                │  `security/wire-format/vulnerability-gitops-record   │
                │  .schema.json`). Then calls the GitHub               │
                │  repository_dispatch API:                            │
                │      event_type: vulnerability-detected              │
                │      (and critical-cve-detected for Critical CVEs)   │
                └─────────────────────────┬────────────────────────────┘
                                          │
                                          ▼
                ┌──────────────────────────────────────────────────────┐
                │           .github/workflows/security.yml             │
                │  ───────────────────────────────────────────────────  │
                │   job sbom-commit   →  security/sboms/<sbom_id>/     │
                │   job vuln-report   →  security/vulns/<date>.json    │
                │   job weekly-digest →  security/vulns/weekly-*.md    │
                │   job cleanup       →  prunes >90d old NDJSONs       │
                │   job sync-sla      →  refreshes SECURITY.md markers │
                └─────────────────────────┬────────────────────────────┘
                                          │
                ┌─────────────────────────┴────────────────────────────┐
                │                                                      │
                ▼                                                      ▼
   ┌──────────────────────────────┐         ┌──────────────────────────────┐
   │  .github/workflows/          │         │  .github/workflows/          │
   │  security-issue.yml          │         │  release.yml (attach-sbom)   │
   │  ─────────────────────────   │         │  ─────────────────────────   │
   │  Opens a Critical CVE issue  │         │  Attaches SBOMs to the       │
   │  with full context + dedup.  │         │  GitHub Release for tag v*   │
   └──────────────────────────────┘         └──────────────────────────────┘
```

---

## Triggers reference

| Workflow / Job                      | Trigger                                                              | Schedule                       |
| ----------------------------------- | -------------------------------------------------------------------- | ------------------------------ |
| `security.yml` / `sbom-commit`      | `push` to `main`, `workflow_dispatch`, `repository_dispatch:supported-version-released` | Daily 03:00 UTC               |
| `security.yml` / `vuln-report`      | `repository_dispatch:vulnerability-detected`                         | event-driven                   |
| `security.yml` / `weekly-digest`    | `workflow_dispatch`                                                  | Mondays 06:00 UTC              |
| `security.yml` / `cleanup`          | `workflow_dispatch`                                                  | Daily 03:00 UTC                |
| `security.yml` / `sync-sla`         | `push` to `main`, `workflow_dispatch`, `repository_dispatch:supported-version-released` | event-driven                   |
| `security-issue.yml` / `open-issue` | `repository_dispatch:critical-cve-detected`, `workflow_dispatch`    | event-driven                   |
| `release.yml` / `attach-sbom`       | tag push `refs/tags/v*`, `workflow_dispatch`                         | event-driven                   |

---

## Daily / weekly cadence

| Time (UTC)  | Day    | What happens                                                                                  |
| ----------- | ------ | --------------------------------------------------------------------------------------------- |
| 03:00       | Daily  | `security.yml` runs: `sbom-commit` (CycloneDX + SPDX → `security/sboms/`), `cleanup` (90d prune) |
| (event)     | Daily  | New CVEs trigger `vuln-report` (append to `security/vulns/<date>.json`); Critical → `security-issue.yml` |
| 06:00       | Mon    | `weekly-digest` aggregates the prior 7 days into `security/vulns/weekly-<ISO-week>.md`        |
| (event)     | Per release | `release.yml` runs `attach-sbom` to attach latest SBOM files to the GitHub Release             |

---

## Operator workflows

### Triage a Critical CVE issue

When a Critical CVE is detected, an issue is auto-opened by
`security-issue.yml`. The issue body contains:

- `id` (CVE-YYYY-NNNN or GHSA-xxxx-yyyy-zzzz)
- `package`, `vulnerable_range`, `fixed_in`
- CVSS v3 score
- `SLA target` (24h ack, 48h triage, 7d patch)
- An action checklist

**Steps:**

1. **Acknowledge** within the SLA — assign yourself, comment "ack".
2. **Confirm the finding** — cross-check with
   [GHSA / NVD / OSV](https://osv.dev/) using the `id` from the issue.
3. **Identify affected versions** — search the issue body for
   `vulnerable_range` and `fixed_in`. Check deployed versions
   via the security dashboard (`/security/risks`).
4. **Open a fix PR** — branch from `main`, bump the package,
   add a test, request review from the service owner. Tag the
   PR with `security` and the same `id`.
5. **Coordinate disclosure** — DM the reporter on the timeline.
   Update the issue checklist.
6. **Publish the advisory** — on patch day, open a
   [GHSA](https://docs.github.com/en/code-security/security-advisories)
   and add a `## Security` entry in the next `CHANGELOG.md` release.

### Override a bot commit

Bot commits use the `github-actions[bot]` identity and open PRs
labelled `security/automated`. To **override**:

1. Open the PR, click **Files changed**.
2. Edit the file in the GitHub UI (or push to the bot's branch
   from a maintainer fork).
3. Add the `[skip-bot]` keyword in the commit message so the bot
   does not try to re-generate on the next run.
4. Merge as normal.

> **Note:** The bot does NOT push directly to `main`. All bot
> changes are PRs and require a human merge.

### Manually trigger

| Want to…                                   | Do this                                                                                              |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Force a fresh SBOM right now               | Actions → `security` → Run workflow → leave defaults                                                 |
| Re-emit a Critical CVE issue for testing   | Actions → `security-issue` → Run workflow → enter `cve_id` (e.g. `GHSA-test-test-test`)             |
| Re-build the weekly digest                 | Actions → `security` → Run workflow → `weekly-digest` job will run on dispatch (gated by `if`)       |
| Manually upload a SBOM to a Release        | `gh release upload v0.1.0 security/sboms/<sbom_id>/*`                                               |
| Disable Dependabot alerts in the meantime  | Settings → Code security and analysis → Dependabot alerts → Disable (not recommended)                |

### Roll back a bot PR

1. Find the PR (search for label `security/automated`).
2. Identify the offending workflow run from the PR comments.
3. If the PR is **not yet merged**: close it. The bot is idempotent —
   the next scheduled run will not re-create it (dedup is keyed on
   `sbom_id` for SBOMs and `id` for vulns).
4. If the PR **is merged**:
   - Revert via `git revert -m 1 <merge-sha>` and open a new PR.
   - For vuln appends, the same `id` will not be re-appended
     (the bot dedups on `id` within the same daily NDJSON).
5. If the bot keeps misbehaving, see
   [Disable the workflows in an incident](#disable-the-workflows-in-an-incident).

### Disable the workflows in an incident

If automation is misbehaving (e.g. flooding issues, mass SBOM
commits, breaking CI), disable the workflows immediately:

```bash
# Option 1: temporarily disable via gh CLI
gh workflow disable security.yml
gh workflow disable security-issue.yml

# Option 2: branch protection override (rare)
# Edit .github/workflows/security.yml and add:
#   if: false
# at the top of every job, then commit directly to main
# (requires a maintainer with admin rights).
```

After the incident:

1. Re-enable the workflows: `gh workflow enable security.yml`
2. Open a post-mortem issue tagged `incident/security-automation`.
3. Add a regression test or guard to prevent recurrence.

### Run from a fork (security researcher flow)

If you fork the repository to investigate or test the security
automation:

- The default `GITHUB_TOKEN` in fork runs **does not have
  `contents: write` or `pull-requests: write` to the upstream
  repo** by design. The auto-PR jobs (`sbom-commit`, `vuln-report`,
  `weekly-digest`, `cleanup`) will fail with `403 Resource not
  accessible by integration`.
- The `security.yml` workflow reads the env var
  `GH_PUSH_TOKEN_FALLBACK`, which resolves to
  `secrets.GH_PUSH_TOKEN || secrets.GITHUB_TOKEN`. To run the
  auto-PR jobs from your fork:
  1. Create a PAT (or GitHub App installation token) on the
     upstream repo with `contents: write` and
     `pull-requests: write`.
  2. On the **fork**, add the token as a secret named
     `GH_PUSH_TOKEN` (Settings → Secrets and variables →
     Actions).
  3. Re-run the workflow from the Actions tab. The jobs will
     use `GH_PUSH_TOKEN` for the upstream calls.
- The read-only jobs (`create-labels` is `contents: read`) work
  fine in fork context with the default token.
- The `security-issue.yml` workflow cannot be triggered from a
  fork via `repository_dispatch` (GitHub blocks cross-repo
  dispatch); use `workflow_dispatch` with a test CVE id
  (`GHSA-test-test-test`) instead.

---

## Common failure modes

| Symptom                                                                 | Likely cause                                          | Fix                                                                                |
| ----------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------- |
| No `security/vulns/<date>.json` created                                 | `repository_dispatch` payload malformed               | Check `Actions` → `security` → run log; verify `client_payload.id` and `severity` |
| Daily NDJSON has duplicate lines                                        | Dedup not running                                     | Verify `jq` is installed in the runner (it is by default) and re-run              |
| `security-issue.yml` opens the same issue repeatedly                    | Dedup search misses the issue                         | Check the title includes the `id` (e.g. `CVE-2024-1234`); titles are matched on substring |
| SBOM commit job fails with `permission denied`                         | `permissions: contents: write` missing                | Restore the `permissions:` block in the job                                        |
| `attach-sbom` job finds no SBOMs                                        | No `sbom-commit` run yet, or `security/sboms/` empty  | Manually trigger `security.yml` → `sbom-commit`                                    |
| `anchore/sbom-action` fails with OOM                                    | Monorepo too large                                    | Add `--fetch-license-info: false` and split into per-service SBOMs               |
| Critical CVE issue never opens                                          | `auto_actionable` field missing from payload         | Verify `vuln-report` step `parse` includes `auto_actionable` from the event       |
| Bot PRs are stuck in a rebase loop                                      | Force-push on a shared branch                         | Ensure bot only pushes to `security/automated/*` branches                          |
| Weekly digest has wrong date range                                      | Cron runs in wrong timezone                           | Cron is UTC; confirm via `date -u` in the run log                                  |

---

## Debugging

### Inspect a run

```bash
# List recent security workflow runs
gh run list --workflow=security.yml --limit 10

# Tail a specific run
gh run view <run-id> --log
```

### Replay a payload locally

```bash
# Get the client_payload of the last vulnerability-detected run
PAYLOAD=$(gh run view <run-id> --json event --jq '.event.payloads[]? | .payload' 2>/dev/null \
           | head -1)
# Re-dispatch it
gh api repos/OWNER/REPO/dispatches \
   -X POST \
   -H "Accept: application/vnd.github+json" \
   -f event_type=vulnerability-detected \
   -f "client_payload[severity]=critical" \
   -f "client_payload[id]=CVE-2099-99999" \
   -f "client_payload[package]=@aicc/test" \
   -f "client_payload[auto_actionable]=true"
```

### Force a re-run

```bash
gh run rerun <run-id> --failed-only
```

---

## Contact

- **Owner:** `@aicc/gitops-manager` (see
  [`.github/CODEOWNERS`](../.github/CODEOWNERS))
- **Escalation:** open an issue labelled `security-automation` and
  assign to GitOpsManager.
- **Sev-1 outage of the automation itself:** page on-call via the
  `#sec-automation` Slack channel (when live).
