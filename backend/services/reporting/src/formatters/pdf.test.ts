import { test, expect } from 'vitest';
import { createLogger } from '@aicc/shared';
import { toPdf } from './pdf.js';
import { buildReportEngine, type Report } from '../engine/report.engine.js';
import { buildInventoryClient } from '../inventory/client.js';

function bigFixtureReport(): Report {
  const rows: Array<Array<string | number | null>> = Array.from({ length: 60 }, (_, i) => [
    `workload-${i}`,
    `namespace-${i % 5}`,
    i * 3,
    i * 2,
    i,
  ]);
  return {
    id: 'r1',
    kind: 'cost_optimization',
    title: 'Fixture Report',
    tenantId: 'tenant-1',
    windowStart: new Date().toISOString(),
    windowEnd: new Date().toISOString(),
    summary: 'A fixture report used to exercise the PDF formatter.',
    sections: [
      {
        title: 'Section one',
        body: 'Body text for section one.',
        bullets: ['bullet a', 'bullet b'],
      },
      { title: 'Section two', body: 'Body text for section two.' },
    ],
    tables: [
      {
        title: 'Sixty rows',
        columns: ['Workload', 'Namespace', 'Current $/mo', 'Recommended $/mo', 'Savings $/mo'],
        rows,
      },
    ],
    charts: [
      {
        title: 'Findings by severity',
        items: [
          { label: 'Critical', value: 4 },
          { label: 'High', value: 9 },
          { label: 'Medium', value: 2 },
        ],
      },
    ],
    generatedAt: new Date().toISOString(),
  };
}

function pagesObjectCount(buf: Buffer): number {
  const match = buf.toString('latin1').match(/\/Type\s*\/Pages[^>]*\/Count\s+(\d+)/);
  if (!match) throw new Error('no /Type /Pages /Count object found');
  return Number(match[1]);
}

/**
 * pdfkit renders text as TJ arrays of hex glyph strings interleaved with
 * kerning offsets (`[<hex> -40 <hex>] TJ`), even with stream compression
 * disabled — plain-text search won't match a whole word. Decode every hex
 * string in the (uncompressed) content stream and concatenate; kerning
 * numbers add no characters, so words reassemble in order.
 */
function decodeAllHexRuns(buf: Buffer): string {
  const text = buf.toString('latin1');
  return Array.from(text.matchAll(/<([0-9a-fA-F]+)>/g))
    .map(([, hex]) => Buffer.from(hex, 'hex').toString('latin1'))
    .join('');
}

test('toPdf produces a multi-page PDF for a large fixture report', async () => {
  const buf = await toPdf(bigFixtureReport());
  expect(buf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
  expect(buf.length).toBeGreaterThan(5 * 1024);
  expect(pagesObjectCount(buf)).toBeGreaterThanOrEqual(2);
});

test('toPdf keeps a small report on exactly one page (no stray footer/header page)', async () => {
  const small: Report = {
    id: 'r2',
    kind: 'topology',
    title: 'Small Report',
    tenantId: 'tenant-1',
    windowStart: new Date().toISOString(),
    windowEnd: new Date().toISOString(),
    summary: 'A tiny fixture report that must fit on a single page.',
    sections: [{ title: 'Overview', body: 'One short section.' }],
    tables: [],
    generatedAt: new Date().toISOString(),
  };
  const buf = await toPdf(small, { compress: false });
  expect(pagesObjectCount(buf)).toBe(1);
  expect(decodeAllHexRuns(buf)).toContain('Page 1 of 1');
});

test('toPdf resolves for every canonical report kind', async () => {
  const logger = createLogger({ service: 'reporting-service-test', version: '0.0.0' });
  const inventory = buildInventoryClient({ logger });
  const engine = buildReportEngine();
  const input = await inventory.fetch('tenant-1');

  const reports = [
    engine.clusterHealth(input),
    engine.infrastructureRisk(input),
    engine.runtimeSecurity(input),
    engine.costOptimization(input),
    engine.topology(input),
    engine.executiveSummary(input),
  ];

  for (const report of reports) {
    const buf = await toPdf(report);
    expect(buf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
  }
});
