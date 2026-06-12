# Scripts are intentionally simple and well-scoped. Most should be runnable
# both from a developer laptop and from CI.
#
# Convention: prefer TypeScript (compiled or via tsx) for anything that
# touches the API or the database. Use Bash only for pure shell glue.

# Setup scripts (run once per machine)
pnpm tsx scripts/setup/bootstrap.ts
pnpm tsx scripts/setup/seed-tenants.ts

# Local dev helpers
pnpm tsx scripts/dev/reset-db.ts
pnpm tsx scripts/dev/replay-event.ts --subject=security.vulnerability.detected.v1 --id=...

# Deploy (from a CI runner with the right creds)
pnpm tsx scripts/deploy/deploy-staging.ts
pnpm tsx scripts/deploy/smoke-test.ts --env=staging

# CI helpers (invoked from .github/workflows/*.yml)
pnpm tsx scripts/ci/changed-workspaces.ts
pnpm tsx scripts/ci/schema-check.ts
