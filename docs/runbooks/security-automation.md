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
6. [Canary tests (T-09) — treat canary matches as P0](#canary-tests-t-09--treat-canary-matches-as-p0)
7. [Downstream routing — POA&M cross-ref for `auto_actionable=false`](#downstream-routing--poam-cross-ref-for-auto_actionablefalse)
8. [Debugging](#debugging)
9. [Contact](#contact)

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
| A `__CANARY__` marker appears in `security/vulns/<date>.json` or in any security API response | **P0 SECURITY INCIDENT** — SecurityArchitect T-09 canary test fired in production | See [Canary tests (T-09)](#canary-tests-t-09--treat-canary-matches-as-p0) below. Page `@security-architect` and `@gitops-manager` immediately. **Do not** attempt to silently remove the line. |

---

## Canary tests (T-09) — treat canary matches as P0

> **Why this section exists:** SecurityArchitect's S2.8 mitigations (T-09,
> test plan § 3.6, cases DC-01..DC-04) include a canary test that
> deliberately submits a SBOM / vulnerability payload containing the
> literal marker `__CANARY__`. The canary asserts that the marker
> **never** appears in any response body, in any committed artifact, or
> in any GitOps-emitted record. The canary is a tripwire: its presence
> in any output means a control failed.

### Detection signals

The S2.10 auto-committer and security-service :4003 projection are
**expected** to see the canary land in the following locations **only
when the canary test itself is running**:

| Location                                                                                            | Expected if canary fired                                                                                              | Page as P0?                                          |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `security/vulns/<YYYY-MM-DD>.json` (NDJSON) — any line whose `id` or `summary` contains `__CANARY__` | **YES** — this is what the canary test does (DC-01). The bot WILL commit a line that matches the canary regex.        | **Yes** — unless the canary owner (`@security-architect`) posted a `#sec-canary-armed` notice in `#sec-automation` within the last 6 hours. |
| `.github/issues` (Critical CVE issue body) — title or body contains `__CANARY__`                    | **YES** — `security-issue.yml` opens issues for every `auto_actionable && severity == 'critical'`. The canary deliberately triggers this (DC-02). | **Yes** — same gating rule. |
| Security-service :4003 REST response bodies — any field containing `__CANARY__`                     | **NO** — the canary asserts this string never reaches an API consumer (DC-03).                                         | **Yes — P0 always.**                                |
| `security/sboms/<sbom_id>.<format>` (CycloneDX / SPDX JSON) — any component or property contains `__CANARY__` | **NO** — the canary asserts the SBOM bytes are sanitized before commit (DC-04).                                       | **Yes — P0 always.**                                |
| `docs/SECURITY.md` rendered HTML — any occurrence of `__CANARY__`                                   | **NO** — the sync-sla job redacts the canary marker, but if you see it on `main`, the redaction step regressed.        | **Yes — P0 always.**                                |
| `CHANGELOG.md` security changelog section — any occurrence                                          | **NO** — the changelog generator must skip records whose `id` or `summary` matches the canary regex.                   | **Yes — P0 always.**                                |

### Triage procedure

1. **Stop the auto-committer.** In an active canary-fire, every new
   run will produce more poisoned artifacts. The fastest way is to
   close the source: revoke the `repository_dispatch` trigger in
   [`.github/workflows/security.yml`](../.github/workflows/security.yml)
   by setting `workflow_dispatch` only, OR disable the workflow
   entirely (Settings → Actions → Disable). See
   [Disable the workflows in an incident](#disable-the-workflows-in-an-incident).
2. **Confirm it is a canary, not a real attack.** Check `#sec-automation`
   for a recent `#sec-canary-armed` post by `@security-architect` or
   `@platform-architect`. The canary owner is the **only** team
   authorized to arm the canary. If no such post exists within 6h,
   treat the match as a real intrusion (P0) and follow the standard
   incident response runbook (`docs/runbooks/incident-response.md`).
3. **Snapshot, do not delete.** If the canary owner confirms it was
   theirs, **do not** `git reset` or `git revert` the canary
   artifacts in place. Take a tarball of the affected files and the
   `Actions` run log first — the canary test asserts on the *committed*
   state, and rolling back will re-trigger the canary.
4. **Notify the canary owner.** Page `@security-architect` in
   `#sec-automation` with: (a) the canary marker, (b) the file path
   and line where it appeared, (c) the run URL, (d) the timestamp
   of the `#sec-canary-armed` post (or confirmation that there was
   none).
5. **Wait for the all-clear.** Do not re-enable the auto-committer
   until `@security-architect` posts a `#sec-canary-disarmed` notice
   in `#sec-automation` AND any in-flight canary artifacts have been
   recorded in the canary test ledger
   (`docs/security/canary-fires.md` — to be created in Sprint 3
   as part of the T-09 canary framework).
6. **Postmortem.** Within 48h of disarm, the canary owner opens a
   P0 postmortem tracking the failure that allowed the marker to
   reach a non-test sink. Root cause categories: (a) input
   sanitization regression in vuln-intel :4008 / sbom-pipeline :4007,
   (b) projection logic in security-service :4003 vuln-projection.ts
   failing to redact, (c) GitOps automation (security.yml,
   security-issue.yml, release.yml) failing to gate on the canary
   regex.

### Distinguisher: expected vs unexpected canary hit (T-09, Sprint 3 dependency)

The triage procedure above assumes the operator must distinguish between
two canary-hit populations:

- **Expected canary hit** — the synthetic test running in CI/prod at a
  scheduled time, owned by `@security-architect` per the S2.8 test plan
  § 3.6 (DC-01..DC-04). The test deliberately emits a `__CANARY__`
  marker to verify that the marker is sanitized. The hit is
  **logged-but-expected**; no page.
- **Unexpected canary hit** — a `__CANARY__` marker appears in the
  absence of an authorized test run. This is either a real intrusion
  (someone is exploiting the data-exfil path) OR a scheduled test that
  failed to post its `#sec-canary-armed` notice. Either way, it is
  **P0** — page immediately.

**The distinguisher field** is `canary_test_run_id` (UUID v4, opaque).
The scheduled canary test, when armed, MUST:

1. Generate a `canary_test_run_id` (UUID v4).
2. Post `#sec-canary-armed <canary_test_run_id>` to `#sec-automation`,
   with the test start time, expected duration, and the run_id itself.
3. Stamp every emitted record, response, and committed artifact with
   the run_id in a top-level `canary_test_run_id` field.
4. On test completion, post `#sec-canary-disarmed <canary_test_run_id>`.
5. Record the run_id in the canary test ledger
   (`docs/security/canary-fires.md` — Sprint 3 deliverable).

**The runbook cross-reference logic** is:

```text
canary_hit_detected:
  if canary_hit.canary_test_run_id is present:
    if canary_hit.canary_test_run_id in docs/security/canary-fires.md:
      # Authorized test run. Log only. No page.
      log(canary_hit)
    else:
      # run_id is present but not in the ledger. Either the test
      # owner forgot to register the run, or someone is forging
      # a run_id to bypass detection. P0.
      page("@security-architect", "@gitops-manager")
  else:
    # No run_id at all. The canary hit is not associated with any
    # authorized test. P0.
    page("@security-architect", "@gitops-manager")
```

**Sprint 2 implementation status:** the `canary_test_run_id` field is
NOT YET emitted by the canary test (T-09 is a Sprint 3 deliverable;
see the S2.8 test plan). In Sprint 2, all canary hits are treated as
unexpected (P0). The distinguisher logic above is the Sprint 3 target
state; operators following this runbook in Sprint 2 should skip the
ledger check and go straight to step 1 of the triage procedure.

**Operator checklist (Sprint 2):**

- [ ] Confirm the canary marker is exactly `__CANARY__` (case-sensitive)
- [ ] Check `#sec-automation` for a recent `#sec-canary-armed` post
      within the last 6h
- [ ] If found, follow the 6-step triage procedure (snapshot, page owner)
- [ ] If not found, treat as P0 and follow the standard incident response runbook

**Operator checklist (Sprint 3+):**

- [ ] All Sprint 2 checks, plus
- [ ] If the canary hit has a `canary_test_run_id` field, look it up
      in `docs/security/canary-fires.md` and follow the distinguisher
      logic above

### Canary regex (Sprint 2)

```text
__CANARY__
```

The marker is matched **case-sensitively** as a literal substring. Any
record, line, or response containing this exact 10-character string
in any field is a canary hit. (Substring-only by design — a real
attacker will not pick this exact token.)

### What this section is NOT

- It is not a recipe for running the canary. The canary is owned by
  `@security-architect`; the test plan is in
  `docs/security/canary-test-plan.md` (T-09 deliverable, Sprint 3).
- It is not authorization to ignore `__CANARY__` matches. There is
  no "expected" channel. If you see it, page.
- It is not a substitute for the standard
  [Disable the workflows in an incident](#disable-the-workflows-in-an-incident)
  procedure. Use that runbook to stop the bleed; come back here for
  the canary-specific follow-up.

---

## Downstream routing — POA&M cross-ref for `auto_actionable=false`

> **Why this section exists:** SecurityArchitect's S2.8 mitigation § 3.6
> (T-03 cross-source consensus gate) requires that a HIGH or CRITICAL
> finding with `auto_actionable == false` MUST still appear in the
> compliance evidence chain as a "verification-pending" POA&M item,
> not be silently dropped. The automation chain (GitOps) and the
> compliance chain (POA&M) serve different audiences; both must
> receive the data.

### The 3 routing paths (LOCKED 2026-06-12, O-3.7 cross-team sign-off)

The 4-condition `auto_actionable` gate determines which downstream
consumer processes a finding. The 3 routing paths are MUTUALLY
EXCLUSIVE based on `(auto_actionable, severity)`:

| `auto_actionable` | `severity`     | Downstream consumer                                          | Output                                                                              | Status flag      |
| ----------------- | -------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------- | ---------------- |
| `true`            | `critical`     | `.github/workflows/security-issue.yml` (via security.yml dispatch) | GitHub issue with labels `security`, `automated`, `cve`, `severity:critical`         | `auto_actioned`  |
| `false`           | `critical` or `high` | **ComplianceOfficer S2.9 POA&M auto-mapping** (via `scan-listener.ts` subscription to `security.vulnerability.detected.v1`) | POA&M item with `status: 'verification-pending'`                                    | `tracked`        |
| any               | any            | security-service :4003 NDJSON appender                      | `security/vulns/<YYYY-MM-DD>.json` line                                             | `recorded`       |

The second row is the POA&M cross-ref. Without it, a HIGH/CRITICAL
that fails the 4-condition gate (e.g. consensus of 1, no fix, or not
in our dep graph) would be silently dropped from the compliance
chain — the very failure mode SecurityArchitect's § 3.6 calls out.

### What the operator needs to know

1. **The compliance service subscribes to the FULL `security.vulnerability.detected.v1` stream** — not a filtered subset. The
   `scan-listener.ts` in `backend/services/compliance/src/subscribers/`
   receives every event, regardless of `auto_actionable`, and applies
   the S2.9 POA&M auto-mapping rule. If you observe a HIGH/CRITICAL
   finding in `security/vulns/<date>.json` with `auto_actionable: false`
   but **no** corresponding POA&M item in the compliance service, that
   is a contract violation — page `@compliance-officer` AND
   `@gitops-manager`.

2. **Records with `auto_actionable: false && severity in {low, medium, unknown}` fall to the third row only.** They are recorded in the
   NDJSON for the audit log (90-day retention per `security/README.md`
   § 'Folder contracts') but are NOT subject to the POA&M
   auto-mapping rule. This is intentional — a low-severity unconfirmed
   finding does not warrant a compliance evidence item, only a
   recorded audit log.

3. **The status flag column** is informational; it is what the S2.9
   POA&M auto-mapping and the GitOps issue opener emit. The flag
   values are not on the wire format (they are downstream artifacts).

### How to verify the routing is working

```bash
# 1. Confirm a recent finding exists in the NDJSON
$ cat security/vulns/$(date -u +%Y-%m-%d).json | jq -r 'select(.severity == "critical") | .id'

# 2. For each critical id above, check whether a corresponding
#    GitHub issue exists (auto_actioned) or a POA&M item exists (tracked)
$ gh issue list --label "severity:critical" --search "<id>" --state all
# (compliance POA&M check is via the compliance service REST API;
#  see docs/runbooks/compliance-service.md for the exact query)
```

If a critical id from step 1 has no issue AND no POA&M item, the
4-condition gate is correctly recording it but the routing is broken.
Page `@compliance-officer` immediately.

### What this section is NOT

- It is not a recipe for opening a POA&M item manually. The
  compliance service auto-creates POA&M items via the S2.9
  auto-mapping. Manual POA&M creation is via the compliance dashboard.
- It is not a fix for the 4-condition gate. If `auto_actionable` is
  `false` because the gate failed (e.g. consensus of 1), the correct
  remediation is to investigate why consensus is low — the POA&M
  cross-ref only ensures the failure is *tracked*, not that it is
  *fixed*.
- It is not authorization to bypass the GitOps critical-CVE issue
  opener. `auto_actionable == true && severity == 'critical'` ALWAYS
  opens an issue, regardless of POA&M status. The two paths run in
  parallel.

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
