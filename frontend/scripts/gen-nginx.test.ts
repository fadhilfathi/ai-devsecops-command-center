import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderNginxConf } from './gen-nginx.mjs';

// Guards against nginx.conf drifting from proxy-table.mjs: regenerate with
// `pnpm --filter ./frontend gen:nginx` whenever proxy-table.mjs changes.
describe('nginx.conf generator', () => {
  it('matches the checked-in nginx.conf', () => {
    const checkedIn = readFileSync(
      fileURLToPath(new URL('../nginx.conf', import.meta.url)),
      'utf8',
    );
    expect(renderNginxConf()).toBe(checkedIn);
  });
});
