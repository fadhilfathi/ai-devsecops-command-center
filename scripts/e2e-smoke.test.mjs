/**
 * Cross-checks e2e-smoke.mjs's standalone `mintAccessToken` against the
 * real `verifyAccessToken` in backend/packages/shared (build it first:
 * `pnpm --filter @aicc/shared build`). If the two implementations ever
 * drift, this fails loudly instead of the e2e workflow silently minting
 * tokens no service accepts.
 *
 * Run: node --test scripts/e2e-smoke.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintAccessToken } from './e2e-smoke.mjs';
import { verifyAccessToken } from '../backend/packages/shared/dist/auth/index.js';

const opts = { secret: 'a'.repeat(32), issuer: 'aicc', audience: 'aicc-api' };

test('mintAccessToken produces a token verifyAccessToken accepts', () => {
  const token = mintAccessToken(
    { sub: 'user-1', role: 'platform_admin', tenantId: 'tenant-1' },
    opts,
  );
  const claims = verifyAccessToken(token, opts);
  assert.equal(claims.sub, 'user-1');
  assert.equal(claims.role, 'platform_admin');
  assert.equal(claims.tenantId, 'tenant-1');
});

test('mintAccessToken with a wrong secret is rejected', () => {
  const token = mintAccessToken(
    { sub: 'user-1', role: 'platform_admin', tenantId: 'tenant-1' },
    { ...opts, secret: 'b'.repeat(32) },
  );
  assert.throws(() => verifyAccessToken(token, opts));
});
