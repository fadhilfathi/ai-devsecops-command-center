import { test, expect } from 'vitest';
import { proposeRemediation, applyRemediation, type Proposal, type RemediationFinding } from './remediation.js';

function pkg(name: string, ecosystem: RemediationFinding['package']['ecosystem'], version: string) {
  return { name, ecosystem, version };
}

test('single finding, single fix → proposes that version', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0001',
        package: pkg('leftpad', 'npm', '1.0.0'),
        fixedVersions: ['1.0.1'],
        severity: 'high',
      },
    ],
  });
  expect(result.unresolved).toEqual([]);
  expect(result.proposals).toHaveLength(1);
  expect(result.proposals[0]).toMatchObject({
    from: '1.0.0',
    to: '1.0.1',
    bump: 'patch',
    risk: 'low',
    resolves: ['CVE-2024-0001'],
    status: 'ok',
  });
});

test('multiple CVEs on one package need the max of the per-finding minimum fixed version', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0001',
        package: pkg('lodash', 'npm', '4.0.0'),
        fixedVersions: ['4.1.0'],
        severity: 'medium',
      },
      {
        cveId: 'CVE-2024-0002',
        package: pkg('lodash', 'npm', '4.0.0'),
        fixedVersions: ['4.3.0', '4.2.0'],
        severity: 'high',
      },
    ],
  });
  expect(result.proposals).toHaveLength(1);
  // finding1's min fix is 4.1.0; finding2's min fix is 4.2.0 (the lower of
  // its two candidates). The binding constraint is the max of those mins.
  expect(result.proposals[0].to).toBe('4.2.0');
  expect(result.proposals[0].resolves.sort()).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
});

test('no fixed version available → unresolved, no proposal', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0003',
        package: pkg('abandoned-pkg', 'npm', '2.0.0'),
        severity: 'critical',
      },
    ],
  });
  expect(result.proposals).toEqual([]);
  expect(result.unresolved).toEqual([
    {
      package: { name: 'abandoned-pkg', ecosystem: 'npm' },
      reason: 'no fixed version at or above the installed version',
    },
  ]);
});

test('unparseable current version → manual_review proposal, not unresolved', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0004',
        package: pkg('weird-pkg', 'npm', 'not-a-version'),
        fixedVersions: ['1.0.0'],
        severity: 'high',
      },
    ],
  });
  expect(result.unresolved).toEqual([]);
  expect(result.proposals).toHaveLength(1);
  expect(result.proposals[0].status).toBe('manual_review');
  expect(result.proposals[0].to).toBe('not-a-version');
});

test('major version bump → high risk', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0005',
        package: pkg('express', 'npm', '3.2.0'),
        fixedVersions: ['4.0.0'],
        severity: 'critical',
      },
    ],
  });
  expect(result.proposals[0]).toMatchObject({ bump: 'major', risk: 'high' });
});

test('minor version bump → medium risk', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0006',
        package: pkg('axios', 'npm', '1.2.0'),
        fixedVersions: ['1.3.0'],
        severity: 'medium',
      },
    ],
  });
  expect(result.proposals[0]).toMatchObject({ bump: 'minor', risk: 'medium' });
});

test('semver pre-release: a release version is preferred over a pre-release of the same core', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0007',
        package: pkg('flaky', 'npm', '1.0.0'),
        fixedVersions: ['1.1.0-beta.1', '1.1.0'],
        severity: 'high',
      },
    ],
  });
  // Both candidates resolve the finding; the lowest one wins, and
  // pre-release sorts below its release per semver rules.
  expect(result.proposals[0].to).toBe('1.1.0-beta.1');
});

test('pypi pre-release ordering differs from semver (a < b < rc < final < post)', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0008',
        package: pkg('requests', 'pypi', '2.0.0'),
        fixedVersions: ['2.1.0rc1', '2.1.0b1', '2.1.0a1'],
        severity: 'high',
      },
    ],
  });
  expect(result.proposals[0].to).toBe('2.1.0a1');
});

test('dedupes multiple findings for the same package+version into one proposal', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0009',
        package: pkg('duplicate-me', 'npm', '1.0.0'),
        fixedVersions: ['1.0.1'],
        severity: 'high',
      },
      {
        cveId: 'CVE-2024-0009',
        package: pkg('duplicate-me', 'npm', '1.0.0'),
        fixedVersions: ['1.0.1'],
        severity: 'high',
      },
    ],
  });
  expect(result.proposals).toHaveLength(1);
  expect(result.proposals[0].resolves).toEqual(['CVE-2024-0009']);
});

test('manifestHint is ecosystem-specific and never an executable action taken by the agent', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0010',
        package: pkg('flask', 'pypi', '1.0'),
        fixedVersions: ['1.1'],
        severity: 'high',
      },
    ],
  });
  expect(result.proposals[0].manifestHint).toBe('pip install flask==1.1');
});

function okProposal(): Proposal {
  return {
    package: { name: 'lodash', ecosystem: 'npm' },
    from: '4.17.20',
    to: '4.17.21',
    bump: 'patch',
    resolves: ['CVE-2021-23337'],
    risk: 'low',
    manifestHint: 'npm install lodash@4.17.21',
    status: 'ok',
  };
}

test('applyRemediation rejects manual_review proposals without calling the integration service', async () => {
  let calls = 0;
  const result = await applyRemediation(
    { integrationId: 'int-1', proposal: { ...okProposal(), status: 'manual_review' } },
    {
      callIntegration: async () => {
        calls += 1;
        return { applied: true, integrationId: 'int-1', kind: 'issue', message: 'opened' };
      },
    },
  );
  expect(result.applied).toBe(false);
  expect(result.kind).toBeNull();
  expect(result.message).toMatch(/manual_review/);
  expect(calls).toBe(0);
});

test('applyRemediation requires an integrationId and never calls the integration service without one', async () => {
  let calls = 0;
  const result = await applyRemediation(
    { integrationId: '', proposal: okProposal() },
    {
      callIntegration: async () => {
        calls += 1;
        return { applied: true, integrationId: 'int-1', kind: 'issue', message: 'opened' };
      },
    },
  );
  expect(result.applied).toBe(false);
  expect(result.kind).toBeNull();
  expect(result.message).toMatch(/integrationId is required/);
  expect(calls).toBe(0);
});

test('applyRemediation passes the integration-service result through unchanged', async () => {
  const downstream = {
    applied: true,
    integrationId: 'int-1',
    kind: 'pull_request' as const,
    url: 'https://github.com/acme/widgets/pull/42',
    number: 42,
    message: 'pull request opened',
  };
  const result = await applyRemediation(
    { integrationId: 'int-1', proposal: okProposal(), context: { cveId: 'CVE-2021-23337' } },
    {
      callIntegration: async (body) => {
        expect(body).toMatchObject({
          integrationId: 'int-1',
          proposal: { to: '4.17.21', status: 'ok' },
          context: { cveId: 'CVE-2021-23337' },
        });
        return downstream;
      },
    },
  );
  expect(result).toEqual(downstream);
});

test('applyRemediation propagates integration-service errors', async () => {
  await expect(
    applyRemediation(
      { integrationId: 'int-1', proposal: okProposal() },
      {
        callIntegration: async () => {
          throw new Error('integration-service remediation request failed: 502');
        },
      },
    ),
  ).rejects.toThrow(/502/);
});

test('a fix only on a lower release line leaves the package unresolved', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0001',
        severity: 'high',
        package: { name: 'lib', ecosystem: 'npm', version: '2.1.0' },
        fixedVersions: ['1.9.4'],
      },
    ],
  });
  expect(result.proposals).toEqual([]);
  expect(result.unresolved[0]?.reason).toBe('no fixed version at or above the installed version');
});

test('mixed release lines pick the fix on or above the installed line', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0002',
        severity: 'high',
        package: { name: 'lib', ecosystem: 'npm', version: '1.2.4' },
        fixedVersions: ['0.9.9', '1.2.9', '2.0.3'],
      },
    ],
  });
  expect(result.proposals[0]?.to).toBe('1.2.9');
  expect(result.proposals[0]?.bump).toBe('patch');
});

test('installed version already fixed → bump none, low risk', () => {
  const result = proposeRemediation({
    findings: [
      {
        cveId: 'CVE-2024-0003',
        severity: 'low',
        package: { name: 'lib', ecosystem: 'npm', version: '1.3.0' },
        fixedVersions: ['1.3.0'],
      },
    ],
  });
  expect(result.proposals[0]?.bump).toBe('none');
  expect(result.proposals[0]?.risk).toBe('low');
});

test('shell metacharacters in a package name never reach the hint', () => {
  const result = proposeRemediation({
    findings: [
      {
        severity: 'high',
        package: { name: 'lib; rm -rf ~', ecosystem: 'npm', version: '1.0.0' },
        fixedVersions: ['1.0.1'],
      },
    ],
  });
  const hint = result.proposals[0]?.manifestHint ?? '';
  expect(hint).not.toContain('rm -rf');
  expect(hint).toMatch(/^manual update required/);
});
