# AionUi Frontend — Architecture & Components

> **Note:** This file is the **architecture and component complement**
> to the top-level `frontend/README.md` (owned by GitOpsManager).
> That file is the *how to run this thing*; this file is the
> *how this thing is built*.

**Owner:** UI/UX Engineer
**Related docs:**
[`docs/architecture/ui-architecture.md`](../docs/architecture/ui-architecture.md),
[`docs/agents/ui-ux-engineer.md`](../docs/agents/ui-ux-engineer.md)

---

## Stack

- **React 18** + **TypeScript** (strict mode)
- **Vite 5** (dev server + bundler)
- **React Router 6** (component routes; lazy-loaded `Graph`)
- **TanStack Query v5** (server state, caching, refetch)
- **Zustand** (small client-state stores, scoped per domain)
- **Axios** (HTTP, with interceptors — see `src/lib/api.ts`)
- **Tailwind CSS 3** + design tokens in `tailwind.config.js`
- **Recharts** (KPI / area / bar charts)
- **Lucide React** (icon system — named imports only)
- **clsx** + **tailwind-merge** (class composition)
- **react-window** (virtualized lists; used by `SbomViewer`)
- **reactflow** (force-directed graph; used by `DependencyGraph` — lazy)

## Layout

```
frontend/
├── index.html
├── package.json
├── vite.config.ts          # /api proxy -> http://localhost:3000
├── tailwind.config.js      # design tokens (see §Design tokens)
├── postcss.config.js
├── tsconfig.json
├── .env.example            # VITE_API_URL
├── README.md               # top-level (GitOpsManager)
├── FRONTEND.md             # this file (UI/UX Engineer)
└── src/
    ├── main.tsx            # QueryClientProvider + BrowserRouter
    ├── App.tsx             # route table
    ├── index.css           # Tailwind + token CSS variables
    ├── components/
    │   ├── Layout.tsx      # Sidebar + Topbar + StatusBar
    │   ├── security/       # S2.6 visualization primitives
    │   │   ├── Sparkline.tsx
    │   │   ├── SecurityScore.tsx
    │   │   ├── SbomViewer.tsx
    │   │   ├── VulnTimeline.tsx
    │   │   ├── RiskHeatmap.tsx
    │   │   └── DependencyGraph.tsx
    │   └── ui/             # primitives (Card, Badge, KpiTile, …)
    ├── routes/             # one file per AionUi screen (single page-path convention)
    │   ├── Dashboard.tsx
    │   ├── Assets.tsx
    │   ├── Incidents.tsx
    │   ├── Vulnerabilities.tsx
    │   ├── SBOM.tsx
    │   ├── Compliance.tsx
    │   ├── Integrations.tsx
    │   ├── Settings.tsx
    │   ├── Graph.tsx
    │   └── NotFound.tsx
    ├── lib/
    │   ├── api.ts          # axios + S2.5 security endpoints
    │   ├── mock.ts         # Sprint 1 + Sprint 2 mocks
    │   └── format.ts
    ├── hooks/
    │   └── useFetch.ts
    └── types/
        └── index.ts        # shared types incl. security types
```

## Design tokens

Tokens are HSL CSS custom properties declared in `src/index.css`,
mapped to Tailwind via `hsl(var(--token))` in `tailwind.config.js`.
Components reference tokens — **never raw hex**. See
[`docs/agents/ui-ux-engineer.md` §4](../docs/agents/ui-ux-engineer.md)
for the canonical palette and contrast guarantees.

## Data flow (Sprint 1 → 2)

- **Sprint 1:** route stubs only. No data wiring.
- **Sprint 2:** route bodies use **TanStack Query** with keys of the
  shape `["aion", resource, ...filters]`. The S2.5 security endpoints
  live under `/api/security/*` and `/api/sbom/*`; `lib/api.ts` is the
  single source of truth and `USE_MOCKS` controls mock vs. live.

## Sprint 2 visualizations (S2.6)

All five live in `src/components/security/` and are wired into
existing routes plus one new route.

| # | Component | Route | Source endpoint | Notes |
|---|-----------|-------|------------------|-------|
| 1 | `SbomViewer`       | `/sbom`, `/sbom/:sbom_id`         | `GET /api/sbom/:id`               | Virtualized with `react-window`. Filters: ecosystem, license, depth. Search by name. CycloneDX export. |
| 2 | `VulnTimeline`     | `/vulnerabilities?view=timeline` | `GET /api/security/vuln-timeline?range=…` | Stacked area, 7d/30d/90d/1y selector. Accessible data-table fallback. |
| 3 | `RiskHeatmap`      | `/dashboard` (collapsible)        | `GET /api/security/risk-heatmap` | Custom SVG grid. ARIA grid pattern. Arrow-key nav. Click → filter `/vulnerabilities`. |
| 4 | `DependencyGraph`  | `/graph/:sbom_id?` (lazy-loaded)  | `GET /api/security/graph/:sbomId` | `reactflow`. Custom node type. Pan/zoom. Side panel. Esc closes. |
| 5 | `SecurityScore`    | `/dashboard` (top)                | `GET /api/security/score`         | Composite (0-100) + 5 sub-metric tiles with sparklines. Band A-F. |

### Performance

- `reactflow` (~80KB gz) is loaded via `React.lazy` so the initial
  bundle stays small.
- `SbomViewer` virtualizes large component lists (default 124, scales
  to 10k+).
- The event stream and timelines use Recharts with
  `isAnimationActive={false}` to avoid jank on update.
- No polling — Sprint 3 wires WebSocket subscription via the
  `event-bus` bridge (Sprint 1 architecture decision).

### Accessibility (WCAG 2.1 AA)

- `SecurityScore` tiles have `aria-label`s describing the value;
  deltas announce improving/worsening direction.
- `VulnTimeline` is a `<svg role="img">` with `aria-label`, and
  exposes an expandable data-table fallback for assistive tech.
- `RiskHeatmap` is a real ARIA grid: `role="grid"`, `role="row"`,
  `role="gridcell"`, full arrow-key navigation (Home, End, PageUp,
  PageDown), Enter to activate. Color is never the only carrier of
  meaning — every cell shows the numeric count and severity label.
- `DependencyGraph` is keyboard-navigable via `reactflow`'s
  built-in tab order; the side panel closes on `Esc`. Each node has
  an `aria-label` summarizing ecosystem, version, and vuln count.

## Path alias

`@/*` → `src/*` (configured in `vite.config.ts` and `tsconfig.json`).

## Page-path convention (locked in S2 retro)

All AionUi screens live in **`src/routes/`** as the project's single
page-path convention. Sprint 1 originally placed the page stubs in
`src/pages/`; the S2.6 follow-up consolidation moved them to
`src/routes/`. Imports in `App.tsx` are now single-path. Do not
introduce new page files under `src/pages/` — it does not exist.

## Scripts

```bash
npm run dev        # Vite dev server, port 5173, /api proxied
npm run build      # tsc + vite build
npm run preview    # serve the production build
npm run typecheck  # tsc --noEmit
npm run lint       # eslint
```

## Future work (post-Sprint-2)

- Real-time event stream via WebSocket (event-bus bridge).
- React Router **data routers** with loaders/actions (so Suspense
  boundaries live at the route level).
- Storybook for every primitive in `components/ui/` and
  `components/security/`.
- axe-core in CI as a hard gate.
- Migrate `DependencyGraph` to a real `d3-force` simulation for true
  force-directed layout (current layout is deterministic by depth).
- Saved views per user (zustand-persist).
