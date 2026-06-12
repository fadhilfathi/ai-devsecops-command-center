# Scripts

> Utility scripts for setup, deployment, CI helpers, and dev workflows.

```
scripts/
├── setup/      # first-time setup (deps, certs, local stack)
├── deploy/     # deploy to staging / prod
├── ci/         # invoked from GitHub Actions
└── dev/        # local dev helpers (db:reset, etc.)
```

All scripts are written in **Node.js + TypeScript** (compiled) or
**Bash** (when shelling out is simpler), and are run via `make` targets
or directly (`pnpm tsx scripts/setup/bootstrap.ts`).
