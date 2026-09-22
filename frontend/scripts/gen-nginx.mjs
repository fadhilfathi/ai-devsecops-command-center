#!/usr/bin/env node
// Generates frontend/nginx.conf from proxy-table.mjs so the two can never
// drift. Run with `pnpm --filter ./frontend gen:nginx` after editing
// proxy-table.mjs; frontend/src/lib/nginx-gen.test.ts asserts the checked-in
// file matches this output.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { PROXY_TABLE } from '../proxy-table.mjs';

export function renderNginxConf(table = PROXY_TABLE) {
  const locations = table
    .map(({ browserPath, port, container, upstreamPath }) => {
      // Exact match for the no-trailing-slash form (e.g. `/api/incidents`)
      // plus a prefix location for subpaths (e.g. `/api/incidents/123`).
      // nginx's `location = <path>` always wins over prefix locations, so
      // order relative to the prefix block below doesn't matter.
      return `    location = ${browserPath} {
        proxy_pass http://${container}:${port}${upstreamPath};
        proxy_set_header Host $host;
    }
    location ${browserPath}/ {
        rewrite ^${browserPath}/(.*)$ ${upstreamPath}/$1 break;
        proxy_pass http://${container}:${port};
        proxy_set_header Host $host;
    }`;
    })
    .join('\n');

  return `# GENERATED FILE — do not edit by hand.
# Source of truth: frontend/proxy-table.ts (see also vite.config.ts).
# Regenerate with: pnpm --filter ./frontend gen:nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

${locations}

    # SPA fallback.
    location / {
        try_files $uri $uri/ /index.html;
    }
}
`;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const outPath = fileURLToPath(new URL('../nginx.conf', import.meta.url));
  writeFileSync(outPath, renderNginxConf());
  console.log(`Wrote ${outPath}`);
}
