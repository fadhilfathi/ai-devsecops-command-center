import { describe, expect, it } from 'vitest';
// `?raw` is Vite's built-in raw-import (typed by the `vite/client` triple-slash
// reference in vite-env.d.ts) — no Node fs/path/@types-node needed.
import appSrc from './App.tsx?raw';
import sidebarSrc from './components/layout/Sidebar.tsx?raw';

// No jsdom/testing-library in this project (see frontend/package.json), so this
// asserts route coverage by reading the source instead of mounting <App />.
// Every href the Sidebar links to must resolve to a <Route path="..."> (or the
// index route) registered in App.tsx — otherwise it silently falls through to
// the `*` NotFound catch-all.

function registeredPaths(): string[] {
  const paths = ['/']; // <Route index .../>
  for (const m of appSrc.matchAll(/<Route\s+path="([^"]+)"/g)) {
    if (m[1] !== '*') paths.push('/' + m[1]);
  }
  return paths;
}

function sidebarHrefs(): string[] {
  return [...sidebarSrc.matchAll(/to:\s*'([^']+)'/g)].map((m) => m[1]);
}

// Turns a react-router path pattern into a matcher: `:param?` (and its
// leading slash) is optional, `:param` matches one segment, `*` matches
// the rest.
function matches(pattern: string, href: string): boolean {
  const source = pattern
    .replace(/\/:[A-Za-z_]+\?/g, '(?:/[^/]+)?')
    .replace(/:[A-Za-z_]+/g, '[^/]+')
    .replace(/\/\*$/, '(?:/.*)?')
    .replace(/\*/g, '.*');
  return new RegExp(`^${source}$`).test(href);
}

describe('Sidebar links resolve to registered routes', () => {
  const routes = registeredPaths();

  it('found both the routes and the nav links (sanity check the regexes)', () => {
    expect(routes.length).toBeGreaterThan(5);
    expect(sidebarHrefs().length).toBeGreaterThan(5);
  });

  it.each(sidebarHrefs())('%s resolves to a registered route', (href) => {
    expect(routes.some((pattern) => matches(pattern, href))).toBe(true);
  });
});
