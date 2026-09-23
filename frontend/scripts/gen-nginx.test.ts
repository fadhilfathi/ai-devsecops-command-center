import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { renderNginxConf } from './gen-nginx.mjs';
import { PROXY_TABLE } from '../proxy-table.mjs';

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

  // S7-4: nginx is the edge, so it must overwrite (not append to) the
  // browser-supplied X-Forwarded-For/X-Real-IP — otherwise a client can
  // spoof the rate-limit key that the backend's TRUST_PROXY_CIDR check
  // would otherwise trust from nginx.
  it('every location block overwrites X-Forwarded-For/X-Real-IP with $remote_addr', () => {
    const conf = renderNginxConf();
    const locationBlocks = conf.match(/location [^{]+\{[^}]*\}/g) ?? [];
    const proxiedBlocks = locationBlocks.filter((block) => block.includes('proxy_pass'));
    expect(proxiedBlocks.length).toBe(PROXY_TABLE.length * 2);
    for (const block of proxiedBlocks) {
      expect(block).toContain('proxy_set_header X-Forwarded-For $remote_addr;');
      expect(block).toContain('proxy_set_header X-Real-IP $remote_addr;');
      expect(block).toContain('proxy_set_header X-Forwarded-Proto $scheme;');
    }
  });
});
