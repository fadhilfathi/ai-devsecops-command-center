import { describe, expect, it } from 'vitest';
import { deriveEcosystem, toAgentFinding } from './lib/api';
import type { Vulnerability } from './types';

// S11-3 — the Remediation screen feeds the agent tasks from
// `api.vulnerabilities()` rows through these two pure helpers (lib/api.ts):
// the wire `Vulnerability` type carries no ecosystem field, and the agent
// inputs spell the finding differently (`cveId`, `package`, `fixedVersions`,
// `informational`). Pure functions, so asserted directly without rendering
// (no jsdom/testing-library in this project — see App.routes.test.ts).

const finding: Vulnerability = {
  id: 'vuln-501',
  cve: 'CVE-2024-3094',
  title: 'xz-utils backdoor (supply-chain compromise)',
  severity: 'critical',
  cvss: 10.0,
  package: 'xz-utils',
  version: '5.6.0',
  fixedIn: '5.6.1',
  status: 'in-progress',
  assetId: 'ast-001',
  detectedAt: '2026-09-30T10:00:00.000Z',
};

describe('deriveEcosystem', () => {
  it('maps scoped names to npm', () => {
    expect(deriveEcosystem('@types/node')).toBe('npm');
  });

  it('maps module paths to go', () => {
    expect(deriveEcosystem('github.com/gin-gonic/gin')).toBe('go');
  });

  it('maps coordinates to maven', () => {
    expect(deriveEcosystem('org.apache.logging.log4j:log4j-core')).toBe('maven');
  });

  it('maps PascalCase ids to nuget', () => {
    expect(deriveEcosystem('Newtonsoft.Json')).toBe('nuget');
  });

  it('maps snake/dot names to pypi', () => {
    expect(deriveEcosystem('python_dateutil')).toBe('pypi');
  });

  it('falls back to npm for bare names', () => {
    expect(deriveEcosystem('lodash')).toBe('npm');
    expect(deriveEcosystem('xz-utils')).toBe('npm');
  });

  it('ignores surrounding whitespace', () => {
    expect(deriveEcosystem('  @angular/core  ')).toBe('npm');
  });
});

describe('toAgentFinding', () => {
  it('maps the exact derived object for a vulnerability with a fix', () => {
    expect(toAgentFinding(finding)).toEqual({
      id: 'vuln-501',
      cveId: 'CVE-2024-3094',
      package: { name: 'xz-utils', ecosystem: 'npm', version: '5.6.0' },
      fixedVersions: ['5.6.1'],
      fixAvailable: true,
      cvss: 10.0,
      severity: 'critical',
    });
  });

  it('maps the exact derived object for a vulnerability without a fix', () => {
    expect(toAgentFinding({ ...finding, cve: undefined, fixedIn: undefined })).toEqual({
      id: 'vuln-501',
      cveId: undefined,
      package: { name: 'xz-utils', ecosystem: 'npm', version: '5.6.0' },
      fixedVersions: [],
      fixAvailable: false,
      cvss: 10.0,
      severity: 'critical',
    });
  });

  it('derives fixAvailable strictly from fixedIn (triage penalizes false)', () => {
    const withFix = toAgentFinding(finding);
    const withoutFix = toAgentFinding({ ...finding, fixedIn: undefined });
    expect(withFix.fixAvailable).toBe(true);
    expect(withoutFix.fixAvailable).toBe(false);
    expect(withFix.fixAvailable).not.toBe(withoutFix.fixAvailable);
  });

  it('passes cvss through to the finding input', () => {
    expect(toAgentFinding(finding).cvss).toBe(10.0);
    expect(toAgentFinding({ ...finding, cvss: 4.3 }).cvss).toBe(4.3);
  });

  it("spells the frontend 'info' severity 'informational' on the wire", () => {
    expect(toAgentFinding({ ...finding, severity: 'info' }).severity).toBe('informational');
  });

  it('derives the ecosystem from the package name', () => {
    expect(toAgentFinding({ ...finding, package: 'github.com/org/repo' }).package).toEqual({
      name: 'github.com/org/repo',
      ecosystem: 'go',
      version: '5.6.0',
    });
  });
});
