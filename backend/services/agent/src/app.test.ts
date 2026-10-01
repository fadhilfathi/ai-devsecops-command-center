import { test, expect } from 'vitest';
import { signAccessToken, AUTH_DEV_DEFAULT_SECRET } from '@aicc/shared';
import { buildServer } from './index.js';

const tokenOpts = { secret: AUTH_DEV_DEFAULT_SECRET, issuer: 'aicc', audience: 'aicc-api' };

test('GET /healthz returns ok', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/healthz' });
  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ status: 'ok' });
  await server.close();
});

test('GET /metrics returns Prometheus metrics', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/metrics' });
  expect(res.statusCode).toBe(200);
  expect(res.body).toContain('http_requests_total');
  await server.close();
});

test('GET /v1/agents returns the registered agent catalog', async () => {
  const server = await buildServer();
  const res = await server.inject({ method: 'GET', url: '/v1/agents' });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(Array.isArray(body.items)).toBe(true);
  await server.close();
});

test('GET /v1/agents without a token is 401 when dev bypass is off', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const res = await server.inject({ method: 'GET', url: '/v1/agents' });
    expect(res.statusCode).toBe(401);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('a token signed with the wrong secret is rejected', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const token = signAccessToken(
      { sub: 'user-1', role: 'platform_admin', tenantId: 'tenant-a' },
      { ...tokenOpts, secret: 'a-completely-different-secret-value' },
    );
    const res = await server.inject({
      method: 'GET',
      url: '/v1/agents/tasks',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(401);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('a token for tenant A plus a forged x-tenant-id header still only sees tenant A data', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'false';
  try {
    const server = await buildServer();
    const tokenA = signAccessToken(
      { sub: 'user-a', role: 'platform_admin', tenantId: 'tenant-a' },
      tokenOpts,
    );
    await server.inject({
      method: 'POST',
      url: '/v1/agents/tasks',
      headers: { authorization: `Bearer ${tokenA}` },
      payload: { kind: 'noop' },
    });
    const res = await server.inject({
      method: 'GET',
      url: '/v1/agents/tasks',
      headers: { authorization: `Bearer ${tokenA}`, 'x-tenant-id': 'tenant-b' },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items.every((t: { tenantId: string }) => t.tenantId === 'tenant-a')).toBe(true);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('POST /v1/agents/tasks with a triage.findings task returns a heuristic triage result', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'true';
  try {
    const server = await buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/v1/agents/tasks',
      headers: { 'x-tenant-id': 'tenant-a' },
      payload: { kind: 'triage.findings', payload: { findings: [{ severity: 'critical' }] } },
    });
    expect(res.statusCode).toBe(202);
    const taskId = res.json().task.id as string;

    // Dispatch runs via setImmediate; poll until it completes.
    let task = res.json().task;
    for (let i = 0; i < 20 && task.status === 'pending'; i++) {
      await new Promise((r) => setImmediate(r));
      const poll = await server.inject({ method: 'GET', url: `/v1/agents/tasks/${taskId}` });
      task = poll.json().task;
    }
    expect(task.status).toBe('completed');
    expect(task.result.decision).toBe('open_incident');
    expect(task.result.priority).toBe('P1');
    expect(task.result.engine).toBe('heuristic');
    expect(Array.isArray(task.result.rationale)).toBe(true);
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('POST /v1/agents/tasks with a remediation.propose task returns a bump proposal', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'true';
  try {
    const server = await buildServer();
    const res = await server.inject({
      method: 'POST',
      url: '/v1/agents/tasks',
      headers: { 'x-tenant-id': 'tenant-a' },
      payload: {
        kind: 'remediation.propose',
        payload: {
          findings: [
            {
              cveId: 'CVE-2024-1234',
              package: { name: 'leftpad', ecosystem: 'npm', version: '1.0.0' },
              fixedVersions: ['1.0.1'],
              severity: 'high',
            },
          ],
        },
      },
    });
    expect(res.statusCode).toBe(202);
    const taskId = res.json().task.id as string;

    let task = res.json().task;
    for (let i = 0; i < 20 && task.status === 'pending'; i++) {
      await new Promise((r) => setImmediate(r));
      const poll = await server.inject({ method: 'GET', url: `/v1/agents/tasks/${taskId}` });
      task = poll.json().task;
    }
    expect(task.status).toBe('completed');
    expect(task.result.proposals[0]).toMatchObject({ to: '1.0.1', bump: 'patch' });
    expect(task.result.engine).toBe('heuristic');
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('POST /v1/agents/tasks with a remediation.apply task opens via the integration service', async () => {
  const prev = process.env.AUTH_DEV_BYPASS;
  process.env.AUTH_DEV_BYPASS = 'true';
  const calls: Array<{ tenantId: string; body: unknown }> = [];
  try {
    const server = await buildServer({
      applyIntegration: async (tenantId, body) => {
        calls.push({ tenantId, body });
        return {
          applied: true,
          integrationId: 'int-1',
          kind: 'issue',
          url: 'https://github.com/acme/widgets/issues/7',
          number: 7,
          message: 'issue opened',
        };
      },
    });
    const res = await server.inject({
      method: 'POST',
      url: '/v1/agents/tasks',
      headers: { 'x-tenant-id': 'tenant-a' },
      payload: {
        kind: 'remediation.apply',
        payload: {
          integrationId: 'int-1',
          proposal: {
            package: { name: 'lodash', ecosystem: 'npm' },
            from: '4.17.20',
            to: '4.17.21',
            bump: 'patch',
            resolves: ['CVE-2021-23337'],
            risk: 'low',
            manifestHint: 'npm install lodash@4.17.21',
            status: 'ok',
          },
        },
      },
    });
    expect(res.statusCode).toBe(202);
    const taskId = res.json().task.id as string;

    // Dispatch runs via setImmediate; poll until it completes.
    let task = res.json().task;
    for (let i = 0; i < 20 && task.status === 'pending'; i++) {
      await new Promise((r) => setImmediate(r));
      const poll = await server.inject({ method: 'GET', url: `/v1/agents/tasks/${taskId}` });
      task = poll.json().task;
    }
    expect(task.status).toBe('completed');
    expect(task.result.applied).toBe(true);
    expect(task.result.url).toBe('https://github.com/acme/widgets/issues/7');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.tenantId).toBe('tenant-a');
    await server.close();
  } finally {
    if (prev === undefined) delete process.env.AUTH_DEV_BYPASS;
    else process.env.AUTH_DEV_BYPASS = prev;
  }
});

test('security headers: no ACAO on a cross-origin request, strict CSP present', async () => {
  const server = await buildServer();
  const res = await server.inject({
    method: 'GET',
    url: '/healthz',
    headers: { origin: 'https://evil.example' },
  });
  expect(res.headers['access-control-allow-origin']).toBeUndefined();
  expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  await server.close();
});
