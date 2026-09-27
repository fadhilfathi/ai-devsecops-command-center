# Sprint 8 — Architecture Notes

Sprint 8 was a public-release-readiness sprint: demo data so the app is
worth looking at with zero setup, the dependency majors deferred from
Sprint 7, a verified user-facing quick-start, the last mock-only
dashboard screens wired to real backend data, and the three Python
security agents actually running (not just built) inside the compose
stack.

## Demo seed data (S8-1)

`AICC_DEMO_SEED=true` makes security, incident, compliance, and
integration services insert a small deterministic fixture set for the
demo tenant on boot — idempotent, off by default, enabled in
`docker-compose.yml`. S8-4 later added an SBOM to the seed and wired
the frontend's `VITE_USE_MOCKS=false` path end-to-end for the security
screens. The Sprint-4 infrastructure services (clusters, kubernetes,
cost, topology) already served fixture data and were out of scope.

## Dependency majors (S8-2)

The React/Tailwind/TypeScript majors deferred from
[S7-2](../sprint-7/README.md) — each needed its own migration pass,
not a blind Dependabot merge.

- **S8-2a**: React 19, Tailwind 4, `recharts` 3, `lucide-react` 1,
  `react-window` 2; `zustand` removed (unused). Tailwind 4 changed two
  defaults that regressed the UI and had to be pinned back explicitly:
  the default focus ring color and the default `cursor: pointer` on
  buttons. See [ADR 0019](../../adr/0019-tailwind-4.md).
- **S8-2b**: TypeScript 6, hoisted to the root `devDependencies` only —
  per-package `typescript`/`@types/node` copies removed, each
  workspace resolves the root's `tsc` via pnpm's ancestor
  `node_modules/.bin` lookup. `@types/node` bumped to `^22.20.4`
  (matches the Node 22 runtime, not the Dependabot-proposed 25).

## Quick-start and the two bugs it uncovered (S8-3)

`docs/quick-start.md` — a verified, user-facing walkthrough covering
mocks-only, the full docker-compose stack, logging in with the seeded
dev user, and running services locally without Docker. Linked from
`README.md` and `docs/architecture/README.md`.

Writing it against the real repo surfaced two bugs:

- the sidebar's Infrastructure section linked to `/infrastructure/*`
  routes that `frontend/src/App.tsx` never registered — they fell
  through to the 404 catch-all despite the page components and backend
  services existing.
- `defaultPort()` in `backend/packages/shared/src/http/index.ts`
  covered only 6 of the 13 services and disagreed with the
  compose/vite-proxy port map for the rest, so `pnpm --filter <svc>
dev` needed a manual `PORT` override to hit the right upstream.

## Real security views (S8-4)

Six of the dashboard's screens were mock-only with no backend route at
all. security-service gained `GET /v1/vulnerabilities`,
`/v1/sbom/components` (+ `/v1/sboms/:id/export`), `/security/score`,
`/security/vuln-timeline`, `/security/risk-heatmap`, `/security/graph`
— all tenant-scoped and auth-gated. The aggregation logic (severity
scoring, SBOM parsing, ecosystem joins, dependency-graph capping) lives
in the pure, unit-tested `services/security-analytics.ts`; the
frontend's 6 mock-only accessors now hit these routes, falling back to
mock data on failure.

Review caught a real correctness bug in the first cut: an empty tenant
(no assets, SBOMs, or findings) computed a perfect 100/A security score
instead of reporting no score at all. Fixed — `composite`/`band` are
now `null` when there's nothing to score.

`sbomExportUrl()` stays mock-only: it still returns a `data:` URL of
the local mock document, because the SBOM page has no async
fetch-then-download flow to receive a real export response.

## Python agents in compose (S8-5)

security-service's `SBOM_PIPELINE_URL`/`VULN_INTEL_URL`/
`DEPENDENCY_INTEL_URL` defaults pointed at `localhost:4007-4009` —
ports Sprint 4 had already assigned to k8s-health, runtime-security,
and inventory — and none of the three Python agents ran in compose at
all. Moved the agents to their own range, 5001-5003 (config default +
Dockerfile `EXPOSE`/`HEALTHCHECK`/`CMD` + README in each), matched
security-service's defaults, and added the three as internal-only
compose services (`depends_on: service_healthy`). Deleted the now-
redundant per-agent `sbom-generator/docker-compose.yml`.
security-service's `/readyz` now also checks the three agents'
liveness endpoints, so the existing e2e-smoke `security` readyz check
covers them.

The first real boot of the three agent images (they had never actually
been run, only built and unit-tested) surfaced four bugs:

- **sbom-generator's Dockerfile never verified the right file.** It
  downloaded the syft release tarball as `/tmp/syft.tgz`, but
  `checksums.txt` names it `syft_<version>_linux_amd64.tar.gz`, so
  `sha256sum -c` couldn't find an entry to check and the image build
  failed outright. Fixed by downloading and verifying under the
  published name.
- **vuln-intel and dependency-intel crashed on boot as non-root.** Both
  write their store/audit log under a relative data directory resolved
  against `WORKDIR /app`, which the non-root runtime user doesn't own.
  Each now gets its own `chown`ed directory under `/var/lib` instead of
  loosening `/app`.
- **sbom-generator's settings loader always raised.**
  `Settings.from_env()` read `workspace_root` off the `Settings` class
  itself, but it's a `default_factory` field with no class-level
  attribute — every boot raised `AttributeError` before the app could
  start. Fixed to read `SBOM_WORKSPACE` from the environment directly,
  falling back to a directory the Dockerfile actually creates.

## How to run it

Same as Sprint 7 for the Node services; the three Python agents now
come up automatically with the rest of the stack:

```bash
pnpm install
pnpm --filter @aicc/security-service dev   # etc., per service
cd frontend && pnpm dev                     # mocks on by default
```

or the full containerised stack, agents included:

```bash
docker compose up --build
node scripts/e2e-smoke.mjs
```

## Manual steps for the maintainer

Unchanged from Sprint 7 — neither has been applied yet:

- Apply the branch protection checklist in
  [`docs/operations/branch-protection.md`](../../operations/branch-protection.md)
  under Settings → Branches.
- Enable GitHub's private vulnerability reporting (Settings →
  Security → Reporting).

## Still deferred

- The SBOM page's export button stays mock-only — it needs an async
  fetch-then-download flow it doesn't have yet.
- sbom-generator's 11 pre-existing failing tests (`test_ssrf.py`'s
  DNS-mocking cases, `test_integration_live.py`'s live-syft cases) —
  not caused by this sprint's changes, not fixed by it either.
- SBOM parsing runs per-request with no size/streaming ceiling beyond
  the shared body-limit middleware — fine at demo scale, revisit if a
  real-world SBOM blows past it.
- Frontend ships a single ~242 KB gzipped JS bundle — no route-level
  code splitting yet, so recharts/reactflow ship on every page.
- Vite is still on 7.x; 8 is out and not evaluated. 14 Dependabot
  PRs are open (grouped Python production/dev bumps for the 3 agents,
  plus GitHub Actions bumps) — none reviewed yet.

## Next steps (Sprint 9)

See `ROADMAP.md`.
