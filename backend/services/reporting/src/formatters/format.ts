/**
 * Report formatters — JSON, Markdown, PDF.
 *
 * PDF rendering (multi-page, headers/footers, tables, bar
 * charts) lives in `./pdf.ts` and is built on pdfkit; it is
 * re-exported here so callers keep a single import.
 */
import type { Report } from '../engine/report.engine.js';

export { toPdf } from './pdf.js';

export type ReportFormat = 'json' | 'md' | 'pdf';

export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

export function toMarkdown(report: Report): string {
  const lines: string[] = [];
  lines.push(`# ${report.title}`);
  lines.push('');
  lines.push(`> ${report.summary}`);
  lines.push('');
  lines.push(`**Window:** ${report.windowStart} → ${report.windowEnd}`);
  lines.push(`**Generated at:** ${report.generatedAt}`);
  lines.push('');
  for (const sec of report.sections) {
    lines.push(`## ${sec.title}`);
    lines.push('');
    lines.push(sec.body);
    if (sec.bullets && sec.bullets.length > 0) {
      lines.push('');
      for (const b of sec.bullets) {
        if (b) lines.push(`- ${b}`);
      }
    }
    lines.push('');
  }
  for (const table of report.tables) {
    lines.push(`## ${table.title}`);
    lines.push('');
    lines.push(`| ${table.columns.join(' | ')} |`);
    lines.push(`| ${table.columns.map(() => '---').join(' | ')} |`);
    for (const row of table.rows) {
      lines.push(
        `| ${row.map((c) => (c === null || c === undefined ? '—' : String(c))).join(' | ')} |`,
      );
    }
    lines.push('');
  }
  return lines.join('\n');
}
