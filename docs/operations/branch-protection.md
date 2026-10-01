# Branch protection — applied settings for `main`

These settings **are applied** to `main` (see the verification commands at
the bottom). They were added in Sprint 12; before that they existed only
as a manual checklist.

The workflow is still a solo maintainer pushing directly to `main`, so
mandatory pull-request review is deliberately NOT required. What is
enforced: CI must pass, and neither force-push nor branch deletion is
possible — including for administrators.

- [x] **Require status checks to pass before merging** — the `ci` jobs
      `Lint & Type-check` and `Build`. `Docker build` is NOT required: it
      only runs on push to `main`, never on PRs, so requiring it would
      deadlock the branch. Note the per-service `Unit tests (...)`
      matrix jobs are not in the required set either; `Build` compiles
      every workspace, so a type error still blocks.
- [ ] **Require branches to be up to date before merging** — not set
      (`strict: false`). Deliberate: it adds churn for a solo
      maintainer pushing straight to `main`.
- [ ] **Do not require pull request reviews** — deliberately unset. The
      documented workflow pushes directly to `main`. Revisit if a second
      maintainer joins.
- [x] **Block force pushes** — `allow_force_pushes: false`.
- [x] **Block branch deletion** — `allow_deletions: false`.
- [ ] **Require signed commits** — not enabled. Turn on
      `required_signatures` once the maintainer configures local commit
      signing.
- [x] **Include administrators** — `enforce_admins: true`, so the rules
      bind the repo owner too and prevent accidental force-push/deletion.

## Verify

    gh api repos/fadhilfathi/ai-devsecops-command-center/branches/main/protection \

    gh api repos/fadhilfathi/ai-devsecops-command-center/private-vulnerability-reporting

## Apply at

`https://github.com/fadhilfathi/ai-devsecops-command-center/settings/branches`
