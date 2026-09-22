/**
 * PDF formatter — multi-page report rendering with pdfkit.
 *
 * Renders the cover block, running header / footer (page N of M),
 * sections with bullets, tables with wrapped cells and repeated
 * header rows, and a small vector bar-chart for report kinds that
 * carry an obvious numeric series (see `report.engine.ts`).
 */
import PDFDocument from 'pdfkit';
import type { Report, ReportChart } from '../engine/report.engine.js';

const PAGE_WIDTH = 612; // US Letter, points
const PAGE_HEIGHT = 792;
const MARGIN = 50;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const HEADER_Y = 20;
const FOOTER_Y = PAGE_HEIGHT - 36;
const CONTENT_TOP = MARGIN + 14;
const CONTENT_BOTTOM = FOOTER_Y - 10;

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626', // red
  high: '#ea580c', // orange
  medium: '#ca8a04', // yellow
  low: '#2563eb', // blue
  info: '#6b7280', // grey
};
const PALETTE = ['#2563eb', '#dc2626', '#059669', '#ca8a04', '#7c3aed', '#0891b2'];

function colorFor(label: string, index: number): string {
  return SEVERITY_COLORS[label.toLowerCase()] ?? PALETTE[index % PALETTE.length]!;
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
  if (doc.y + needed > CONTENT_BOTTOM) {
    doc.addPage();
    doc.y = CONTENT_TOP;
  }
}

function drawBarChart(doc: PDFKit.PDFDocument, chart: ReportChart): void {
  const rowHeight = 16;
  const barMaxWidth = CONTENT_WIDTH - 160;
  const height = 24 + chart.items.length * rowHeight + 10;
  ensureSpace(doc, height);
  doc.font('Helvetica-Bold').fontSize(11).fillColor('#111827').text(chart.title, MARGIN);
  doc.moveDown(0.3);
  const max = Math.max(1, ...chart.items.map((i) => i.value));
  const startY = doc.y;
  let y = startY;
  chart.items.forEach((item, idx) => {
    const barWidth = Math.max(2, (item.value / max) * barMaxWidth);
    doc
      .font('Helvetica')
      .fontSize(9)
      .fillColor('#374151')
      .text(item.label, MARGIN, y + 2, {
        width: 100,
        lineBreak: false,
      });
    doc.rect(MARGIN + 105, y, barWidth, rowHeight - 4).fill(colorFor(item.label, idx));
    doc
      .fillColor('#111827')
      .text(String(item.value), MARGIN + 105 + barWidth + 6, y + 2, { lineBreak: false });
    y += rowHeight;
  });
  doc.y = y + 6;
  doc.x = MARGIN;
}

function measureColumnWidths(
  columns: string[],
  rows: Array<Array<string | number | null>>,
): number[] {
  const raw = columns.map((c, i) => {
    const headerLen = c.length;
    const contentLen = rows.reduce((max, r) => {
      const cell = r[i];
      const len = cell === null || cell === undefined ? 1 : String(cell).length;
      return Math.max(max, len);
    }, 0);
    return Math.max(headerLen, Math.min(contentLen, 60));
  });
  const total = raw.reduce((a, b) => a + b, 0) || 1;
  return raw.map((w) => Math.max(50, (w / total) * CONTENT_WIDTH));
}

function drawTableHeader(doc: PDFKit.PDFDocument, columns: string[], widths: number[]): number {
  const y = doc.y;
  const rowHeight = 18;
  doc.rect(MARGIN, y, CONTENT_WIDTH, rowHeight).fill('#e5e7eb');
  let x = MARGIN;
  doc.font('Helvetica-Bold').fontSize(9).fillColor('#111827');
  columns.forEach((col, i) => {
    doc.text(col, x + 4, y + 5, { width: widths[i]! - 8, lineBreak: false });
    x += widths[i]!;
  });
  doc.y = y + rowHeight;
  doc.x = MARGIN;
  return rowHeight;
}

function drawTable(
  doc: PDFKit.PDFDocument,
  table: { title: string; columns: string[]; rows: Array<Array<string | number | null>> },
): void {
  ensureSpace(doc, 40);
  doc.font('Helvetica-Bold').fontSize(12).fillColor('#111827').text(table.title, MARGIN);
  doc.moveDown(0.3);
  const widths = measureColumnWidths(table.columns, table.rows);
  drawTableHeader(doc, table.columns, widths);

  table.rows.forEach((row, rowIndex) => {
    doc.font('Helvetica').fontSize(9);
    const cellHeights = row.map((cell, i) => {
      const text = cell === null || cell === undefined ? '—' : String(cell);
      return doc.heightOfString(text, { width: widths[i]! - 8 });
    });
    const rowHeight = Math.max(14, ...cellHeights) + 6;

    if (doc.y + rowHeight > CONTENT_BOTTOM) {
      doc.addPage();
      doc.y = CONTENT_TOP;
      drawTableHeader(doc, table.columns, widths);
    }

    const y = doc.y;
    if (rowIndex % 2 === 1) {
      doc.rect(MARGIN, y, CONTENT_WIDTH, rowHeight).fill('#f9fafb');
    }
    let x = MARGIN;
    doc.fillColor('#1f2937');
    row.forEach((cell, i) => {
      const text = cell === null || cell === undefined ? '—' : String(cell);
      doc.text(text, x + 4, y + 3, { width: widths[i]! - 8 });
      x += widths[i]!;
    });
    doc.y = y + rowHeight;
    doc.x = MARGIN;
  });
  doc.moveDown(0.8);
}

export interface ToPdfOptions {
  /** Disable stream compression — useful in tests that grep the raw content stream. */
  compress?: boolean;
}

export function toPdf(report: Report, options: ToPdfOptions = {}): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'LETTER',
      margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
      bufferPages: true,
      compress: options.compress ?? true,
    });
    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('error', reject);
    doc.on('end', () => resolve(Buffer.concat(chunks)));

    doc.y = CONTENT_TOP;

    // Cover block.
    doc.font('Helvetica-Bold').fontSize(20).fillColor('#111827').text(report.title, MARGIN);
    doc.moveDown(0.4);
    doc.font('Helvetica').fontSize(10).fillColor('#1f2937').text(report.summary, MARGIN);
    doc.moveDown(0.3);
    doc
      .font('Helvetica')
      .fontSize(9)
      .fillColor('#6b7280')
      .text(`Window: ${report.windowStart} -> ${report.windowEnd}`, MARGIN);
    doc.text(`Generated: ${report.generatedAt}`, MARGIN);
    doc.moveDown(0.8);

    for (const sec of report.sections) {
      ensureSpace(doc, 30);
      doc.font('Helvetica-Bold').fontSize(13).fillColor('#111827').text(sec.title, MARGIN);
      doc.moveDown(0.2);
      doc.font('Helvetica').fontSize(10).fillColor('#1f2937').text(sec.body, MARGIN, doc.y, {
        width: CONTENT_WIDTH,
        align: 'justify',
      });
      if (sec.bullets && sec.bullets.length > 0) {
        doc.moveDown(0.2);
        for (const b of sec.bullets) {
          if (!b) continue;
          ensureSpace(doc, 14);
          doc
            .font('Helvetica')
            .fontSize(9)
            .fillColor('#1f2937')
            .text(`•  ${b}`, MARGIN + 10, doc.y, { width: CONTENT_WIDTH - 10 });
        }
      }
      doc.moveDown(0.6);
    }

    for (const table of report.tables) {
      drawTable(doc, table);
    }

    for (const chart of report.charts ?? []) {
      drawBarChart(doc, chart);
    }

    // Stamp header / footer on every page now that the page count is known.
    // pdfkit auto-flows to a new page if a `text()` call would cross the
    // bottom margin — drop it to 0 while stamping so footer text near the
    // page edge doesn't spawn an extra trailing page.
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      const originalBottomMargin = doc.page.margins.bottom;
      doc.page.margins.bottom = 0;
      const footerY = doc.page.height - 30;

      doc
        .font('Helvetica')
        .fontSize(8)
        .fillColor('#9ca3af')
        .text(report.title, MARGIN, HEADER_Y, { width: CONTENT_WIDTH / 2, lineBreak: false });
      doc.text(report.kind, MARGIN, HEADER_Y, {
        width: CONTENT_WIDTH,
        align: 'right',
        lineBreak: false,
      });
      doc.text(`Generated ${report.generatedAt}`, MARGIN, footerY, {
        width: CONTENT_WIDTH / 2,
        lineBreak: false,
      });
      doc.text(`Page ${i - range.start + 1} of ${range.count}`, MARGIN, footerY, {
        width: CONTENT_WIDTH,
        align: 'center',
        lineBreak: false,
      });

      doc.page.margins.bottom = originalBottomMargin;
    }

    doc.end();
  });
}
