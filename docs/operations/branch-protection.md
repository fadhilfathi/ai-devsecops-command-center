# Branch protection — recommended settings for `main`

These settings are **not currently applied**. This is a checklist for
the maintainer to apply manually under
**Settings → Branches → Branch protection rules → `main`**. Nothing
in CI enforces or verifies this document.

The current workflow is a solo maintainer pushing directly to `main`
(no mandatory PR review). The checklist below hardens the branch
without blocking that workflow.

- [ ] **Require status checks to pass before merging** — select the
      `ci` jobs: `Lint & Type-check`, `Unit tests`, `Build`. Do not
      require `Docker build` (only runs on push to `main`, not PRs).
- [ ] **Require branches to be up to date before merging** — optional;
      skip if it creates too much churn for a solo maintainer.
- [ ] **Do not require pull request reviews** — leave unchecked; the
      documented workflow pushes directly to `main`. Revisit if a
      second maintainer joins.
- [ ] **Block force pushes** — enable "Do not allow force pushes".
- [ ] **Block branch deletion** — enable "Do not allow deletions".
- [ ] **Require signed commits** — optional, enable if the maintainer
      sets up commit signing locally; not currently enforced.
- [ ] **Include administrators** — enable so the rules apply even to
      the repo owner, preventing accidental force-push/deletion.

Apply at: `https://github.com/fadhilfathi/ai-devsecops-command-center/settings/branches`
