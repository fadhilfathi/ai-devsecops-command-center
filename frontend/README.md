# Frontend (AionUi)

> The single-page web app for the AI-DevSecOps Command Center. Built
> with Vite, React 19, TypeScript, and a small set of well-considered
> libraries.

## Screens

| Path               | Screen              | Purpose                                                  |
| ------------------ | ------------------- | -------------------------------------------------------- |
| `/`                | **Dashboard**       | Live posture, open incidents, top risks, recent activity |
| `/assets`          | **Assets**          | Inventory of code, images, services, IaC                 |
| `/incidents`       | **Incidents**       | Active and historical incidents, with playbooks          |
| `/vulnerabilities` | **Vulnerabilities** | Findings, with filters, dedup, and remediation tracking  |
| `/sbom`            | **SBOM**            | CycloneDX browser, diff, license and provenance          |
| `/compliance`      | **Compliance**      | Posture per framework, evidence, attestations            |
| `/integrations`    | **Integrations**    | Configure GitHub, GitLab, scanners, etc.                 |
| `/settings`        | **Settings**        | Users, roles, tenants, API tokens, audit log access      |

## Architecture

```
frontend/
├── public/            # static assets
├── src/
│   ├── components/    # reusable, presentational, no business logic
│   ├── screens/       # one folder per screen (composition only)
│   ├── hooks/         # data fetching, mutations, subscriptions
│   ├── services/      # HTTP / WS clients; the only place that touches the network
│   ├── styles/        # tokens, themes, design system
│   ├── utils/         # small, pure helpers
│   └── types/         # generated types from backend/packages/shared/contracts
└── tests/             # unit + e2e
```

## Conventions

- **Component-first**: a screen composes components. No business logic in JSX.
- **Hooks for state**: data fetching, mutations, and live subscriptions all
  live in custom hooks.
- **No direct `fetch`** in components — go through `src/lib/api.ts`.
- **Strict accessibility**: every interactive element is reachable by
  keyboard and has an accessible name.
- **Strict TypeScript**: `strict`, `noUncheckedIndexedAccess`,
  `noImplicitAny` are non-negotiable.
- **No barrel files for components**: import directly from the file.
  (Reduces Vite HMR confusion.)

## Stack

- **Vite** — bundler / dev server
- **React 19** — UI
- **TypeScript** — types
- **TanStack Query** — server state caching
- **Zustand** — small global UI state
- **React Router** — routing
- **Radix UI** — accessible primitives
- **Tailwind CSS** — utility styling
- **Vitest + Testing Library** — unit / integration tests
- **Playwright** — e2e tests

## Running

```bash
pnpm --filter ai-devsecops-frontend dev
# or
make dev-frontend
```

The dev server runs on `:5173`. There is no API gateway: each
browser-facing resource is proxied straight to the backend service that
owns it — see `PROXY_TABLE` in `proxy-table.mjs`, the single source of
truth for both the dev proxy (`vite.config.ts`) and the production nginx
image. `nginx.conf` is **generated** from that table — never edit it by
hand; run `pnpm --filter ./frontend gen:nginx` after changing
`proxy-table.mjs` (a test asserts they can't drift).

## Running against real services

By default the app renders from `src/lib/*.mock.ts` — no backend
required. To hit the real services:

```bash
# from the repo root
docker compose up postgres redis kubernetes-service k8s-health-service \
  runtime-security-service inventory-service cost-intelligence-service \
  topology-service

cd frontend
cp .env.example .env
# edit .env: VITE_USE_MOCKS=false
pnpm dev
```

`get<T>()` in `src/lib/api.ts` falls back to mock data (with a console
warning) on any network error or non-2xx response, so a page never
crashes if one service isn't running. When mocks are off and a call
fails, the failure is also recorded in `apiHealth` (`src/lib/api.ts`),
and the app shell shows a "Degraded: showing sample data for N
endpoint(s)" banner instead of failing silently. `VITE_TENANT_ID`
(default `demo-tenant`) is sent as the `x-tenant-id` header — the dev
shortcut until S6-2 wires real auth.

`frontend/Dockerfile` accepts `VITE_USE_MOCKS` (default `true`) and
`VITE_TENANT_ID` (default `demo-tenant`) as build args — Vite inlines
`import.meta.env.VITE_*` at build time, so these can't be changed at
container runtime. `docker-compose.yml`'s `frontend` service builds
with `VITE_USE_MOCKS=false` so the compose stack exercises the real
proxy path.

### Endpoints with no backend route yet (mock-only)

These accessors in `src/lib/api.ts` always return mock data, regardless
of `VITE_USE_MOCKS` — there is no matching backend route (marked with a
`ponytail:` comment at each call site; see S6-1):

- `api.vulnerabilities()` — no `GET /vulnerabilities` on security-service
- `api.sbom()` — no SBOM components-listing endpoint
- `api.securityScore()`, `api.vulnTimeline()`, `api.riskHeatmap()`,
  `api.graphData()` — no security-service routes for these yet

## See also

- [`/docs/architecture/system-architecture.md`](../../docs/architecture/system-architecture.md)
- [`/docs/architecture/agent-topology.md`](../../docs/architecture/agent-topology.md)
- [`/CONTRIBUTING.md`](../../CONTRIBUTING.md)
