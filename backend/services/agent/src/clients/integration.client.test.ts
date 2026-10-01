import { afterEach, describe, expect, test, vi } from 'vitest';
import { AUTH_DEV_DEFAULT_SECRET, type Logger, type ServiceConfig } from '@aicc/shared';
import { createIntegrationClient } from './integration.client.js';

function noopLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

const cfg = {
  auth: {
    secret: AUTH_DEV_DEFAULT_SECRET,
    issuer: 'aicc',
    audience: 'aicc-api',
  },
} as ServiceConfig;

const tenant = 'tenant-a';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('createIntegrationClient', () => {
  test.each(['TimeoutError', 'AbortError'])(
    'a fetch rejected with %s throws a timeout error instead of resolving',
    async (name) => {
      const inits: (RequestInit | undefined)[] = [];
      vi.stubGlobal(
        'fetch',
        vi.fn(async (_url: string, init?: RequestInit) => {
          inits.push(init);
          throw Object.assign(new Error('The operation was aborted.'), { name });
        }),
      );
      const applyIntegration = createIntegrationClient(cfg, noopLogger());
      await expect(
        applyIntegration(tenant, { integrationId: 'int-1', proposal: {} }),
      ).rejects.toThrow(/timed out after 15000ms/);
      // The abort wiring that makes the 15s timeout real must be present.
      expect(inits[0]?.signal).toBeInstanceOf(AbortSignal);
    },
  );

  test('a timeout error is distinguishable from an HTTP failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('upstream-secret-detail', { status: 502 })),
    );
    const applyIntegration = createIntegrationClient(cfg, noopLogger());
    // HTTP failure keeps its bare-status shape (no upstream body) — and
    // never masquerades as a timeout.
    await expect(
      applyIntegration(tenant, { integrationId: 'int-1', proposal: {} }),
    ).rejects.toThrow('integration-service remediation request failed: 502');
  });
});
