import { afterEach, describe, expect, test } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { EcosystemSchema } from '@aicc/shared';
import { buildServer } from '../index.js';
import {
  renderRemediationBody,
  selectRemediationTarget,
  type RemediationContext,
  type RemediationProposal,
} from './integrations.js';

const proposal: RemediationProposal = {
  package: { name: 'left-pad', ecosystem: 'npm' },
  from: '1.0.0',
  to: '1.3.0',
  bump: 'minor',
  resolves: ['CVE-2023-1234', 'GHSA-abcd-efgh'],
  risk: 'low',
  manifestHint: '"left-pad": "^1.3.0"',
  status: 'ok',
};

const context: RemediationContext = {
  findingId: 'finding-1',
  cveId: 'CVE-2023-1234',
  assetId: 'asset-1',
  repo: 'acme/widgets#feature-x',
};

describe('selectRemediationTarget', () => {
  test('opens a pull request for an ok proposal with an explicit #branch suffix', () => {
    expect(selectRemediationTarget('ok', 'acme/widgets#feature-x')).toEqual({
      kind: 'pull_request',
      repo: 'acme/widgets',
      head: 'feature-x',
    });
  });

  test('defaults to an issue when no #branch suffix is given', () => {
    expect(selectRemediationTarget('ok', 'acme/widgets')).toEqual({
      kind: 'issue',
      repo: 'acme/widgets',
    });
  });

  test('defaults to an issue for manual_review proposals even with a #branch suffix', () => {
    expect(selectRemediationTarget('manual_review', 'acme/widgets#feature-x')).toEqual({
      kind: 'issue',
      repo: 'acme/widgets',
    });
  });

  test('treats an empty #branch suffix as no branch', () => {
    expect(selectRemediationTarget('ok', 'acme/widgets#')).toEqual({
      kind: 'issue',
      repo: 'acme/widgets',
    });
  });
});

describe('renderRemediationBody', () => {
  test('is deterministic for the same proposal and context', () => {
    expect(renderRemediationBody(proposal, context)).toBe(renderRemediationBody(proposal, context));
  });

  test('puts the manifestHint in a fenced code block', () => {
    const body = renderRemediationBody(proposal, context);
    expect(body).toContain('```\n"left-pad": "^1.3.0"\n```');
    expect(body).toContain('- **Update**: `1.0.0` -> `1.3.0`');
    expect(body).toContain('`CVE-2023-1234`, `GHSA-abcd-efgh`');
  });

  test('renders the context fields and omits the section when absent', () => {
    const withContext = renderRemediationBody(proposal, context);
    expect(withContext).toContain('### Context');
    expect(withContext).toContain('- **Finding**: `finding-1`');
    expect(withContext).toContain('- **Repo**: `acme/widgets#feature-x`');
    expect(renderRemediationBody(proposal)).not.toContain('### Context');
  });
});

// ---- app-level behaviour via the real route ----

type FetchStub = { calls: [string, RequestInit][]; restore: () => void };

function stubFetch(respond: (url: string) => Response): FetchStub {
  const calls: [string, RequestInit][] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push([url, init ?? {}]);
    return respond(url);
  }) as typeof globalThis.fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

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

async function createIntegration(
  server: FastifyInstance,
  tenant: string,
  provider: string,
  config: Record<string, unknown>,
): Promise<string> {
  const res = await server.inject({
    method: 'POST',
    url: '/v1/integrations',
    headers: { 'x-tenant-id': tenant },
    payload: { provider, name: `${provider} integration`, config },
  });
  expect(res.statusCode).toBe(201);
  return res.json().integration.id as string;
}

function postRemediation(
  server: FastifyInstance,
  integrationId: string,
  tenant: string,
  body: Record<string, unknown>,
) {
  return server.inject({
    method: 'POST',
    url: `/v1/integrations/${integrationId}/remediation`,
    headers: { 'x-tenant-id': tenant },
    payload: body,
  });
}

const proposalPayload = { ...proposal, manifestHint: '"left-pad": "^1.3.0"' };

// The repositories are in-memory per buildServer() instance, so each
// test creates its integration and applies remediation on one server.
async function withServer(fn: (server: FastifyInstance) => Promise<void>): Promise<void> {
  const server = await buildServer();
  try {
    await fn(server);
  } finally {
    await server.close();
  }
}

test('dryRun returns without a single outbound fetch call', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(() => {
    throw new Error('fetch must not be called for a dry run');
  });
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      context,
      dryRun: true,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ opened: false, dryRun: true, kind: 'pull_request' });
    expect(stub.calls).toHaveLength(0);
  });
});

test('an integration id from another tenant is 404', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-b', {
      proposal: proposalPayload,
      dryRun: true,
    });
    expect(res.statusCode).toBe(404);
  });
});

test('a non-github integration is 409', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'gitlab', {
      owner: 'acme',
      repo: 'widgets',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      dryRun: true,
    });
    expect(res.statusCode).toBe(409);
  });
});

test('a github integration without a token is 422', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      dryRun: true,
    });
    expect(res.statusCode).toBe(422);
    expect(res.json().message).toMatch(/token/);
  });
});

test('a GitHub 500 becomes a generic 502 with no upstream body text', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(
    () => new Response('upstream-secret-detail', { status: 500, headers: { 'x-oops': '1' } }),
  );
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', { proposal: proposalPayload });
    expect(res.statusCode).toBe(502);
    expect(stub.calls).toHaveLength(1);
    expect(res.body).not.toContain('upstream-secret-detail');
    expect(res.json().message).not.toContain('upstream-secret-detail');
  });
});

test('a clean proposal without a #branch opens an issue', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(
    () =>
      new Response(
        JSON.stringify({ html_url: 'https://github.com/acme/widgets/issues/7', number: 7 }),
        { status: 201 },
      ),
  );
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', { proposal: proposalPayload });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      opened: true,
      dryRun: false,
      kind: 'issue',
      url: 'https://github.com/acme/widgets/issues/7',
      number: 7,
    });
    const [url, init] = stub.calls[0]!;
    expect(url).toContain('/repos/acme/widgets/issues');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer ghp_test');
    expect(String(JSON.parse(String(init.body)).body)).toContain(
      '```\n"left-pad": "^1.3.0"\n```',
    );
  });
});

test('a clean proposal with a #branch suffix opens a pull request', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(
    () =>
      new Response(
        JSON.stringify({ html_url: 'https://github.com/acme/widgets/pull/9', number: 9 }),
        { status: 201 },
      ),
  );
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      pat: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      context,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ opened: true, kind: 'pull_request', number: 9 });
    const [url, init] = stub.calls[0]!;
    expect(url).toContain('/repos/acme/widgets/pulls');
    expect(JSON.parse(String(init.body))).toMatchObject({ head: 'feature-x' });
  });
});

test('a context.repo naming a different owner/repo is 422 and never reaches GitHub', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(() => {
    throw new Error('fetch must not be called for a mismatched remediation target');
  });
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      context: { ...context, repo: 'other-org/widgets#feature-x' },
    });
    expect(res.statusCode).toBe(422);
    expect(res.json().message).toMatch(/configured repository/);
    expect(stub.calls).toHaveLength(0);
  });
});

test('a context.repo with a foreign repo and no #branch is 422 too — nothing is silently ignored', async () => {
  trackEnv('AICC_CREDENTIAL_KEYS', undefined);
  const stub = stubFetch(() => {
    throw new Error('fetch must not be called for a mismatched remediation target');
  });
  restored.push(stub.restore);
  await withServer(async (server) => {
    const id = await createIntegration(server, 'tenant-a', 'github', {
      owner: 'acme',
      repo: 'widgets',
      token: 'ghp_test',
    });
    const res = await postRemediation(server, id, 'tenant-a', {
      proposal: proposalPayload,
      context: { ...context, repo: 'other-org/widgets' },
    });
    expect(res.statusCode).toBe(422);
    expect(res.json().message).toMatch(/configured repository/);
    expect(stub.calls).toHaveLength(0);
  });
});

// The ecosystem enum is single-sourced in @aicc/shared so the agent-side
// remediation module and `RemediationRequestSchema` cannot drift; pin the
// wire values, which are mirrored as `RemediationEcosystem` string
// literals in frontend/src/types/index.ts.
test('the shared ecosystem enum matches the remediation wire contract', () => {
  expect(EcosystemSchema.options).toEqual(['npm', 'pypi', 'maven', 'go', 'cargo', 'nuget']);
});
