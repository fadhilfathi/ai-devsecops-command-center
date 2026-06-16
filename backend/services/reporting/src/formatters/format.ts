/**
 * Report formatters — JSON, Markdown, PDF.
 *
 * The PDF output is a minimal Sprint 4 implementation: it
 * produces a single-page text PDF (1.4 spec) using a tiny
 * hand-rolled writer. The Sprint 5 refactor will swap in a
 * richer template (charts, colours, headers / footers).
 */
import type { Report } from '../engine/report.engine.js';

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
      lines.push(`| ${row.map((c) => (c === null || c === undefined ? '—' : String(c))).join(' | ')} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

/** A minimal PDF 1.4 generator. Outputs a single text page. */
export function toPdf(report: Report): Buffer {
  // Build the text content as a series of (text, font size, x, y) ops.
  const lines: Array<{ text: string; size: number; bold?: boolean }> = [];
  lines.push({ text: report.title, size: 18, bold: true });
  lines.push({ text: report.summary, size: 10 });
  lines.push({ text: `Window: ${report.windowStart} -> ${report.windowEnd}`, size: 9 });
  lines.push({ text: `Generated: ${report.generatedAt}`, size: 9 });
  lines.push({ text: '', size: 8 });
  for (const sec of report.sections) {
    lines.push({ text: sec.title, size: 13, bold: true });
    lines.push({ text: sec.body, size: 10 });
    if (sec.bullets) {
      for (const b of sec.bullets) {
        if (b) lines.push({ text: `  - ${b}`, size: 9 });
      }
    }
    lines.push({ text: '', size: 8 });
  }
  for (const table of report.tables) {
    lines.push({ text: table.title, size: 12, bold: true });
    lines.push({ text: table.columns.join(' | '), size: 9, bold: true });
    for (const row of table.rows) {
      lines.push({ text: row.map((c) => (c === null || c === undefined ? '—' : String(c))).join(' | '), size: 9 });
    }
    lines.push({ text: '', size: 8 });
  }

  // Build the page content stream.
  const pageHeight = 792; // US Letter
  const pageWidth = 612;
  const margin = 50;
  const lineHeight = 14;
  const startY = pageHeight - margin;
  const ops: string[] = [];
  let y = startY;
  for (const line of lines) {
    if (y < margin) break; // single-page; truncate if needed
    const font = line.bold ? '/F2' : '/F1';
    const size = line.size;
    const text = (line.text ?? '').replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
    ops.push(`BT ${font} ${size} Tf 50 ${y} Td (${text}) Tj ET`);
    y -= lineHeight;
  }
  // Silence unused-variable warning for the unused width constant.
  void pageWidth;
  const stream = ops.join('\n');

  // Minimal PDF 1.4 document with one page.
  const objects: string[] = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>`,
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>',
  ];

  let out = '%PDF-1.4\n';
  const offsets: number[] = [];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) {
    out += `${o.toString().padStart(10, '0')} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(out, 'latin1');
}
