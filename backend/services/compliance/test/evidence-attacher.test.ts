// Unit tests for EvidenceAttacher.attach() — the scan-report -> MappingInput
// path (kind is hardcoded to 'unknown', matching the pre-existing
// toMappingInput() default; see evidence-attacher.ts).
// Run with: vitest run (pnpm --filter @aicc/compliance-service test)

import { test, expect } from 'vitest';
import { EvidenceAttacher, type AttachScanInput } from '../src/evidence/evidence-attacher.js';
import { InMemoryBlobStore } from '../src/evidence/blob-store.memory.js';
import { buildEvidenceRepository } from '../src/repositories/evidence.repository.js';
import { buildPoamRepository, PoamService } from '../src/poam/index.js';
import { MappingEngine } from '../src/control-mapper/index.js';
import mappingRules from '../src/control-mapper/mapping-rules.json' with { type: 'json' };

function makeBus() {
  const events: Array<{ type: string; tenantId?: string; data?: unknown }> = [];
  return {
    events,
    publish: async (e: { type: string; tenantId?: string; data?: unknown }) => {
      events.push({ type: e.type, tenantId: e.tenantId, data: e.data });
    },
    subscribe: async () => {},
    close: async () => {},
  };
}

function buildAttacher() {
  const bus = makeBus();
  const evidenceRepo = buildEvidenceRepository();
  const poamRepo = buildPoamRepository();
  const poamService = new PoamService({ repo: poamRepo, bus: bus as never });
  const mappingEngine = new MappingEngine({ rules: mappingRules as never });
  const attacher = new EvidenceAttacher({
    store: new InMemoryBlobStore(),
    evidenceRepo,
    mappingEngine,
    poamService,
    bus: bus as never,
  });
  return { attacher, evidenceRepo, poamRepo, bus };
}

function scanReportInput(findings: unknown[]): AttachScanInput {
  return {
    tenantId: 'tenant-1',
    assetId: 'asset-1',
    scanId: 'scan-1',
    tool: 'trivy',
    sbom: {},
    scanReport: { findings },
  };
}

test('a scan report with a critical KEV CVE and a medium non-KEV CVE attaches evidence and POA&M items to exactly the expected controls (not CIS 16)', async () => {
  const { attacher, evidenceRepo, poamRepo } = buildAttacher();

  const input = scanReportInput([
    {
      id: 'CVE-1',
      cveId: 'CVE-2024-0001',
      severity: 'critical',
      kev: true,
      assetId: 'asset-1',
      packageName: 'pkg-a',
    },
    {
      id: 'CVE-2',
      cveId: 'CVE-2024-0002',
      severity: 'medium',
      kev: false,
      assetId: 'asset-1',
      packageName: 'pkg-b',
    },
  ]);

  const result = await attacher.attach(input);

  // Expected controls, computed from mapping-rules.json for
  // subjectKind: 'vulnerability' (default), kind: 'unknown':
  //   cis-7  (severity_gte medium)      -> both findings
  //   nist-si-2 (always)                -> both findings
  //   nist-ra-5 (always)                -> both findings
  //   nist-si-7 (kev === true)          -> CVE-1 only
  // cis-16 (kind_eq 'sca') must NOT match: kind is 'unknown'.
  const expectedControls = ['7', 'RA-5', 'SI-2', 'SI-7'];
  expect(result.attachedControls.slice().sort()).toEqual(expectedControls);

  const evidence = await evidenceRepo.list('tenant-1');
  expect(Array.from(new Set(evidence.map((e) => e.controlId))).sort()).toEqual(expectedControls);
  expect(evidence.some((e) => e.controlId === '16')).toBe(false);

  // 4 tuples for CVE-1 (7, SI-2, RA-5, SI-7) + 3 tuples for CVE-2 (7, SI-2, RA-5).
  const poams = await poamRepo.list({ tenantId: 'tenant-1' });
  expect(poams.items.length).toBe(7);
  expect(poams.items.some((p) => p.controlId === '16')).toBe(false);
});

test('a scan report with zero findings creates no POA&M items', async () => {
  const { attacher, evidenceRepo, poamRepo } = buildAttacher();

  const result = await attacher.attach(scanReportInput([]));

  expect(result.attachedControls).toEqual([]);
  expect(result.poamCreated).toBe(0);

  const poams = await poamRepo.list({ tenantId: 'tenant-1' });
  expect(poams.items.length).toBe(0);

  const evidence = await evidenceRepo.list('tenant-1');
  expect(evidence.length).toBe(0);
});
