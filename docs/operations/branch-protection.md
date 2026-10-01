# Branch protection — applied settings for `main`

These settings **are applied** to `main` (see the verification commands at
the bottom). They were added in Sprint 12; before that they existed only
as a manual checklist.

Enforced today: `Lint & Type-check` must pass before anything lands on
`main`, and neither force-push nor branch deletion is possible —
including for administrators.

Mandatory pull-request review is deliberately NOT required (solo
maintainer). But note this gate still means work arrives via a branch and
a PR: `main` rejects direct pushes, because a required check cannot have
run on a commit that is not yet pushed. That is the intended effect, not
an obstacle to work around.

- [x] **Require status checks to pass before merging** — **`Lint &
    Type-check` only.** This was narrowed from an initial
      `Lint & Type-check` + `Build`, for a reason worth recording: - `Unit tests` is a **matrix** job. Its check names are reported
      per instance (`Unit tests (backend/services/auth)`,
      `Unit tests (frontend)`, …), so requiring the bare string
      `Unit tests` never matches and requiring all ~20 instances is
      brittle — adding a workspace to the matrix would silently
      bypass the gate. - `Build` _does_ run on PRs. It appeared to skip only because it
      `needs: [lint, test-unit, test-python]` and its dependencies had
      not finished; a skipped-dependency cascade is not an `if:
      push` guard.
      `Lint & Type-check` is the one gate that both runs on every PR and
      has a stable name. It runs `pnpm lint`, `pnpm typecheck`, and
      `pnpm format:check`, so formatting, lint, and type errors all
      block. Test failures are still visible on the PR and block via
      review, but are not a hard gate.
- [x] **Note:** enabling this gate means `main` no longer accepts direct
      pushes. Work lands on a branch and merges through a PR — which is
      the point, and was the outcome when Sprint 12 turned this on (see
      PR #86).
- [ ] **Require branches to be up to date before merging** — not set
      (`strict: false`). Deliberate: it forces a rebase-and-retry loop
      on every merge for a solo maintainer.
- [ ] **Do not require pull request reviews** — deliberately unset, so a
      PR can still be self-merged. Revisit if a second maintainer joins.
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
