import { describe, expect, it } from 'vitest';
import type { VulnerabilityFinding, SecurityScan, Asset } from '@aicc/shared';
import type { SbomRecord } from '../repositories/sbom.repository.js';
import {
  buildDependencyGraph,
  computeRiskHeatmap,
  computeSecurityScore,
  computeVulnTimeline,
  ecosystemFromPurl,
  extractSbomComponents,
  severityToCvss,
  toWireVulnerabilities,
} from './security-analytics.js';

const TENANT = 'tenant-a';

function finding(overrides: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
  return {
    id: 'f-1',
    tenantId: TENANT,
    scanId: 'scan-1',
    severity: 'high',
    title: 'demo finding',
    description: 'demo',
    status: 'open',
    createdAt: '2026-06-01T00:00:00.000Z',
    updatedAt: '2026-06-01T00:00:00.000Z',
    packageName: 'lodash',
    packageVersion: '4.17.20',
    ...overrides,
  };
}

function scan(overrides: Partial<SecurityScan> = {}): SecurityScan {
  return {
    id: 'scan-1',
    tenantId: TENANT,
    assetId: 'asset-1',
    status: 'succeeded',
    findingsCount: 1,
    scanner: 'trivy',
    createdAt: '2026-06-01T00:00:00.000Z',
    updatedAt: '2026-06-01T00:00:00.000Z',
    ...overrides,
  };
}

const SBOM_DOC = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { timestamp: '2026-06-01T00:00:00Z', component: { 'bom-ref': 'root' } },
  components: [
    {
      type: 'library',
      'bom-ref': 'lodash@4.17.20',
      name: 'lodash',
      version: '4.17.20',
      purl: 'pkg:npm/lodash@4.17.20',
    },
    {
      type: 'library',
      'bom-ref': 'chalk@5.3.0',
      name: 'chalk',
      version: '5.3.0',
      purl: 'pkg:npm/chalk@5.3.0',
    },
  ],
  dependencies: [
    { ref: 'root', dependsOn: ['lodash@4.17.20'] },
    { ref: 'lodash@4.17.20', dependsOn: ['chalk@5.3.0'] },
  ],
};

function sbomRecord(overrides: Partial<SbomRecord> = {}): SbomRecord {
  return {
    id: 'sbom-1',
    tenantId: TENANT,
    assetId: 'asset-1',
    format: 'cyclonedx',
    document: SBOM_DOC,
    createdAt: '2026-06-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('ecosystemFromPurl', () => {
  it('maps known purl types', () => {
    expect(ecosystemFromPurl('pkg:npm/lodash@4.17.20')).toBe('npm');
    expect(ecosystemFromPurl('pkg:golang/x/crypto')).toBe('go');
    expect(ecosystemFromPurl('pkg:gem/rails')).toBe('rubygems');
  });
  it('falls back to other for unknown/missing purl', () => {
    expect(ecosystemFromPurl(undefined)).toBe('other');
    expect(ecosystemFromPurl('pkg:cocoapods/Foo')).toBe('other');
  });
});

describe('severityToCvss', () => {
  it('is deterministic and monotonic with severity', () => {
    expect(severityToCvss('critical')).toBeGreaterThan(severityToCvss('high'));
    expect(severityToCvss('high')).toBeGreaterThan(severityToCvss('medium'));
    expect(severityToCvss('info')).toBe(0.1);
  });
});

describe('toWireVulnerabilities', () => {
  it('joins findings through scans to the asset, maps severity/status', () => {
    const out = toWireVulnerabilities(
      [finding({ severity: 'unknown', status: 'resolved', cveId: 'CVE-2024-1' })],
      [scan()],
    );
    expect(out).toEqual([
      expect.objectContaining({
        assetId: 'asset-1',
        severity: 'info', // unknown -> info
        status: 'remediated',
        cve: 'CVE-2024-1',
        package: 'lodash',
      }),
    ]);
  });

  it('leaves assetId empty when the scan is missing', () => {
    const out = toWireVulnerabilities([finding({ scanId: 'missing' })], []);
    expect(out[0]!.assetId).toBe('');
  });
});

describe('extractSbomComponents', () => {
  it('parses CycloneDX components, computes depth, and joins vuln counts', () => {
    const findings = [
      finding({ packageName: 'lodash', packageVersion: '4.17.20', severity: 'high' }),
    ];
    const out = extractSbomComponents([sbomRecord()], findings);
    expect(out).toHaveLength(2);
    const lodash = out.find((c) => c.name === 'lodash')!;
    expect(lodash.ecosystem).toBe('npm');
    expect(lodash.depth).toBe(0);
    expect(lodash.vulnerabilities).toBe(1);
    expect(lodash.highestSeverity).toBe('high');
    const chalk = out.find((c) => c.name === 'chalk')!;
    expect(chalk.depth).toBe(1);
    expect(chalk.vulnerabilities).toBe(0);
  });
});

describe('buildDependencyGraph', () => {
  it('builds nodes + edges and caps by severity', () => {
    const findings = [
      finding({ packageName: 'lodash', packageVersion: '4.17.20', severity: 'critical' }),
    ];
    const graph = buildDependencyGraph([sbomRecord()], findings, 'sbom-1', 1);
    expect(graph.nodes).toHaveLength(1);
    expect(graph.nodes[0]!.label).toBe('lodash');
    expect(graph.edges).toEqual([]); // chalk was dropped by the cap, so root->lodash's child edge is gone
  });

  it('keeps edges between two retained nodes', () => {
    const graph = buildDependencyGraph([sbomRecord()], [], 'sbom-1', 50);
    expect(graph.edges).toEqual([{ source: 'lodash@4.17.20', target: 'chalk@5.3.0' }]);
  });
});

describe('computeSecurityScore', () => {
  it('penalizes open findings by severity and clamps to [0, 100]', () => {
    const findings = [
      finding({ id: 'f1', severity: 'critical', status: 'open' }),
      finding({ id: 'f2', severity: 'high', status: 'open' }),
      finding({ id: 'f3', severity: 'critical', status: 'resolved' }), // resolved, excluded
    ];
    const assets: Asset[] = [
      {
        id: 'asset-1',
        tenantId: TENANT,
        type: 'service',
        name: 'a',
        ownerId: 'o',
        metadata: {},
        tags: [],
        createdAt: '',
        updatedAt: '',
      },
    ];
    const score = computeSecurityScore(findings, assets, [sbomRecord()]);
    // penalty = 10 (critical) + 5 (high) = 15 -> composite 85 -> band B
    expect(score.hasData).toBe(true);
    expect(score.composite).toBe(85);
    expect(score.band).toBe('B');
    const critical = score.subMetrics.find((m) => m.id === 'critical-vulns')!;
    expect(critical.value).toBe(1);
    const coverage = score.subMetrics.find((m) => m.id === 'sbom-coverage')!;
    expect(coverage.value).toBe(100); // asset-1 has an sbom
  });

  it('never goes below 0', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      finding({ id: `f${i}`, severity: 'critical' }),
    );
    const assets: Asset[] = [
      {
        id: 'asset-1',
        tenantId: TENANT,
        type: 'service',
        name: 'a',
        ownerId: 'o',
        metadata: {},
        tags: [],
        createdAt: '',
        updatedAt: '',
      },
    ];
    const score = computeSecurityScore(findings, assets, []);
    expect(score.composite).toBe(0);
    expect(score.band).toBe('F');
  });

  it('returns hasData: false with null composite/band for a tenant with no assets, SBOMs, or findings', () => {
    const score = computeSecurityScore([], [], []);
    expect(score.hasData).toBe(false);
    expect(score.composite).toBeNull();
    expect(score.band).toBeNull();
    expect(score.subMetrics).toEqual([]);
  });

  it('scores a tenant with assets but zero findings as 100/A with hasData: true', () => {
    const assets: Asset[] = [
      {
        id: 'asset-1',
        tenantId: TENANT,
        type: 'service',
        name: 'a',
        ownerId: 'o',
        metadata: {},
        tags: [],
        createdAt: '',
        updatedAt: '',
      },
    ];
    const score = computeSecurityScore([], assets, [sbomRecord()]);
    expect(score.hasData).toBe(true);
    expect(score.composite).toBe(100);
    expect(score.band).toBe('A');
  });
});

describe('computeVulnTimeline', () => {
  it('buckets findings by day and severity within the range', () => {
    const today = new Date().toISOString().slice(0, 10);
    const findings = [
      finding({ severity: 'critical', createdAt: `${today}T00:00:00.000Z` }),
      finding({ severity: 'critical', createdAt: `${today}T01:00:00.000Z` }),
      finding({ severity: 'low', createdAt: '2000-01-01T00:00:00.000Z' }), // outside 7d range
    ];
    const points = computeVulnTimeline(findings, '7d');
    expect(points).toHaveLength(7);
    const last = points[points.length - 1]!;
    expect(last.date).toBe(today);
    expect(last.critical).toBe(2);
    expect(points.every((p) => p.low === 0)).toBe(true);
  });
});

describe('computeRiskHeatmap', () => {
  it('derives ecosystem from the joined SBOM component, defaulting to other', () => {
    const findings = [
      finding({ packageName: 'lodash', severity: 'high' }),
      finding({ packageName: 'totally-unknown-pkg', severity: 'medium' }),
    ];
    const components = extractSbomComponents([sbomRecord()], []);
    const heatmap = computeRiskHeatmap(findings, components);
    expect(heatmap.totalVulns).toBe(2);
    const npmHigh = heatmap.cells.find((c) => c.ecosystem === 'npm' && c.severity === 'high')!;
    expect(npmHigh.count).toBe(1);
    const otherMedium = heatmap.cells.find(
      (c) => c.ecosystem === 'other' && c.severity === 'medium',
    )!;
    expect(otherMedium.count).toBe(1);
    expect(heatmap.ecosystems).toHaveLength(8);
  });
});
