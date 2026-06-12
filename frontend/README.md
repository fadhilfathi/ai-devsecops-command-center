# Frontend (AionUi)

> The single-page web app for the AI-DevSecOps Command Center. Built
> with Vite, React 18, TypeScript, and a small set of well-considered
> libraries.

## Screens

| Path              | Screen            | Purpose                                                       |
| ----------------- | ----------------- | ------------------------------------------------------------- |
| `/`               | **Dashboard**     | Live posture, open incidents, top risks, recent activity      |
| `/assets`         | **Assets**        | Inventory of code, images, services, IaC                      |
| `/incidents`      | **Incidents**     | Active and historical incidents, with playbooks               |
| `/vulnerabilities`| **Vulnerabilities** | Findings, with filters, dedup, and remediation tracking   |
| `/sbom`           | **SBOM**          | CycloneDX browser, diff, license and provenance               |
| `/compliance`     | **Compliance**    | Posture per framework, evidence, attestations                 |
| `/integrations`   | **Integrations**  | Configure GitHub, GitLab, scanners, etc.                      |
| `/settings`       | **Settings**      | Users, roles, tenants, API tokens, audit log access           |

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
- **No direct `fetch`** in components — go through `src/services/`.
- **Strict accessibility**: every interactive element is reachable by
  keyboard and has an accessible name.
- **Strict TypeScript**: `strict`, `noUncheckedIndexedAccess`,
  `noImplicitAny` are non-negotiable.
- **No barrel files for components**: import directly from the file.
  (Reduces Vite HMR confusion.)

## Stack

- **Vite** — bundler / dev server
- **React 18** — UI
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
pnpm --filter @aicc/frontend dev
# or
make dev-frontend
```

The dev server runs on `:5173` and proxies API calls to `:3000`
(configured in `vite.config.ts`).

## See also

- [`/docs/architecture/system-architecture.md`](../../docs/architecture/system-architecture.md)
- [`/docs/architecture/agent-topology.md`](../../docs/architecture/agent-topology.md)
- [`/CONTRIBUTING.md`](../../CONTRIBUTING.md)
