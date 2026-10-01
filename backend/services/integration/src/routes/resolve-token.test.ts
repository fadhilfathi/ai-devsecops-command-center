import { afterEach, expect, test } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../index.js';

// A misconfigured `AICC_CREDENTIAL_KEYS` (a raw key pasted without its
// `keyId:` prefix) must yield a clean 422 whose body never contains the
// key material. The route harness (withServer/createIntegration/stubFetch/
// trackEnv) lives in integrations.test.ts, which another workstream owns
// and does not export, so this file keeps local copies of what it needs.

const pastedKey = Buffer.from('k'.repeat(32)).toString('base64');

const proposal = {
  package: { name: 'left-pad', ecosystem: 'npm' },
  from: '1.0.0',
  to: '1.3.0',
  bump: 'minor',
  resolves: ['CVE-2023-1234'],
  risk: 'low',
  manifestHint: '"left-pad": "^1.3.0"',
  status: 'ok',
};

const restored: Array<() => void> = [];
afterEach(() => {
  while (restored.length > 0) restored.pop()!();
});

function trackEnv(name: string, value: string | undefined): void {
  const prev = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  restored.push(() => {
    if (prev === undefined) delete process.env[name];
    else process.env[name] = prev;
  });
}

function stubFetch(): { calls: unknown[]; restore: () => void } {
  const calls: unknown[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    calls.push(undefined);
    throw new Error('fetch must not be called');
  }) as typeof globalThis.fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

async function withServer(fn: (server: FastifyInstance) => Promise<void>): Promise<void> {
  const server = await buildServer();
  try {
    await fn(server);
  } finally {
    await server.close();
  }
}

async function createIntegration(server: FastifyInstance): Promise<string> {
  const res = await server.inject({
    method: 'POST',
    url: '/v1/integrations',
    headers: { 'x-tenant-id': 'tenant-a' },
    payload: {
      provider: 'github',
      name: 'github integration',
      config: { owner: 'acme', repo: 'widgets', token: 'ghp_test' },
    },
  });
  expect(res.statusCode).toBe(201);
  return res.json().integration.id as string;
}

test('a malformed AICC_CREDENTIAL_KEYS is 422 and the body never contains the key material', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', pastedKey);
  const stub = stubFetch();
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server);
    const res = await server.inject({
      method: 'POST',
      url: `/v1/integrations/${id}/remediation`,
      headers: { 'x-tenant-id': 'tenant-a' },
      payload: { proposal },
    });
    expect(res.statusCode).toBe(422);
    expect(res.json().message).toMatch(/credential could not be decrypted/);
    expect(res.body).not.toContain(pastedKey);
    expect(stub.calls).toHaveLength(0);
  });
});
