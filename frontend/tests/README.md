# Frontend test suites

Frontend tests live alongside components in co-located `*.test.tsx` files
(Vitest + React Testing Library). This directory hosts:

- `e2e/` — Playwright end-to-end suites
- `visual/` — Chromatic / Playwright visual regression
- `a11y/` — axe-core accessibility tests
- `performance/` — Lighthouse CI

## Conventions

- One Playwright spec per product surface (e.g. `dashboard.spec.ts`).
- Page Object Model under `e2e/pages/`.
- Deterministic data: every spec uses a seeded fixture.

## Running

```bash
npm test                   # unit (Vitest)
npm run test:e2e           # Playwright
npm run test:visual        # Chromatic / Playwright
npm run test:a11y          # axe
```
