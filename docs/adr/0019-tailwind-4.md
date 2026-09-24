# 0019 — Tailwind 3 → 4

Status: accepted
Date: 2026-09-24

## Context

Tailwind 3 (`tailwindcss@3.4.19`) was an open Dependabot major (S8-2,
deferred from S7-2). Tailwind 4 changes the build integration (CSS-first
config, no more PostCSS plugin required for Vite) and renames a handful
of utilities.

## Decision

- Replace the PostCSS pipeline (`postcss.config.js` + `tailwindcss` +
  `autoprefixer` plugins) with `@tailwindcss/vite`, added directly to
  `vite.config.ts`. Tailwind 4 ships its own vendor-prefixing; no
  separate `autoprefixer` is needed.
- Delete `postcss.config.js` and `tailwind.config.js`. The theme
  extension (`aion.*`/`severity.*` colors, `fontFamily`, one
  `boxShadow`) was small, so it moved into `src/index.css` via
  `@theme` rather than kept as a JS config loaded through `@config` —
  the smaller, single-source-of-truth diff.
- `darkMode: 'class'` was dropped: grepped the codebase for `dark:`
  utilities and found none — the app is dark-only via `color-scheme:
dark` on `:root`, so the config option was dead weight.
- `content: [...]` was dropped: Tailwind 4 auto-detects source files
  in the project; no explicit content glob is needed.
- `@tailwind base/components/utilities` → `@import 'tailwindcss';`.

### Breaking changes actually hit

1. **`@apply` can no longer apply a custom component class.**
   `.aion-card-hover { @apply aion-card ...; }` failed to build
   (`Cannot apply unknown utility class 'aion-card'`) because Tailwind
   4's `@apply` only resolves real utilities, not other `@layer
components` classes. Fixed by inlining `aion-card`'s three
   utilities directly into `.aion-card-hover` (one file,
   `src/index.css`).
2. **`outline-none` semantics changed.** `outline-none` now sets
   `outline-style: none` (still counted for Windows High Contrast
   Mode); the old "hide but still counted" behavior is
   `outline-hidden`. Six `focus:outline-none` usages that pair a
   removed outline with a `focus:ring-*` replacement were renamed to
   `focus:outline-hidden` (`Button.tsx`, `Topbar.tsx`, `Login.tsx`,
   `SbomViewer.tsx`, `RiskHeatmap.tsx`).
3. **`shadow-sm` renamed to `shadow-xs`** (old `shadow` sizing scale
   shifted down one step). One usage in `DependencyGraph.tsx`.

### Renamed utilities checked and not present

`bg-opacity-*`/`text-opacity-*`/`ring-opacity-*`, `flex-shrink-*`/
`flex-grow-*`, `overflow-ellipsis` — grepped, none used.

## Consequences

- Built CSS still contains the `aion-*`/`severity-*` color tokens
  (verified via `grep dist/assets/index-*.css`). Two v4 default changes
  did alter rendering and were pinned back in `Button.tsx`: the default
  ring colour is now `currentColor` (set `ring-aion-accent/40` on every
  variant) and buttons no longer get `cursor: pointer` (added
  explicitly). Every `border`/`divide` usage already names a colour, so
  the new `currentColor` border default changes nothing.
- One dependency removed from the frontend (`autoprefixer`, `postcss`)
  in favor of `@tailwindcss/vite`.
- Future Tailwind config changes go in `src/index.css`'s `@theme`
  block; there is no `tailwind.config.js` anymore.
