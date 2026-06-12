import { useCallback, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { Card } from "@/components/ui/Card";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { titleCase } from "@/lib/format";
import type { Ecosystem, RiskHeatmap, RiskHeatmapCell, Severity } from "@/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * RiskHeatmap — 2D ecosystem × severity heatmap, custom SVG grid.
 *
 * Sprint 2 / S2.6 visualization #3. Consumes
 * `GET /api/security/risk-heatmap` (S2.5). Click a cell to navigate
 * to `/vulnerabilities?ecosystem=X&severity=Y` (deep-link filter).
 *
 * Accessibility:
 *  - role="grid" / "row" / "gridcell" pattern.
 *  - Arrow keys move focus (left/right between ecosystems,
 *    up/down between severities).
 *  - Home/End jump to row edges, PageUp/PageDown jump 5 rows.
 *  - Enter activates the cell (filter dispatch).
 *  - Each cell has an aria-label with its count.
 *  - Color is never the only carrier of meaning — every cell shows
 *    the numeric count and the severity label.
 */
export function RiskHeatmap() {
  const { data, loading } = useFetch(api.riskHeatmap, []);

  const ecosystems = data?.ecosystems ?? [];
  const cellMap = useMemo(() => {
    const m = new Map<string, RiskHeatmapCell>();
    (data?.cells ?? []).forEach((c) => m.set(`${c.ecosystem}:${c.severity}`, c));
    return m;
  }, [data]);

  const max = useMemo(() => {
    let mx = 0;
    (data?.cells ?? []).forEach((c) => {
      if (c.count > mx) mx = c.count;
    });
    return mx;
  }, [data]);

  const [focus, setFocus] = useState<{ eco: number; sev: number }>({ eco: 0, sev: 0 });
  const cellRefs = useRef<(SVGGElement | null)[][]>([]);

  const move = useCallback(
    (dCol: number, dRow: number) => {
      setFocus((f) => ({
        eco: clamp(f.eco + dCol, 0, Math.max(0, ecosystems.length - 1)),
        sev: clamp(f.sev + dRow, 0, Math.max(0, SEVERITIES.length - 1)),
      }));
    },
    [ecosystems.length]
  );

  const activate = useCallback((eco: Ecosystem, sev: Severity) => {
    // Filter dispatch — set query params and navigate to /vulnerabilities.
    const params = new URLSearchParams({ ecosystem: eco, severity: sev });
    window.location.assign(`/vulnerabilities?${params.toString()}`);
  }, []);

  const onKey = (e: React.KeyboardEvent<SVGGElement>) => {
    switch (e.key) {
      case "ArrowRight": e.preventDefault(); move(1, 0); break;
      case "ArrowLeft":  e.preventDefault(); move(-1, 0); break;
      case "ArrowDown":  e.preventDefault(); move(0, 1); break;
      case "ArrowUp":    e.preventDefault(); move(0, -1); break;
      case "Home":       e.preventDefault(); setFocus((f) => ({ eco: 0,                sev: f.sev })); break;
      case "End":        e.preventDefault(); setFocus((f) => ({ eco: ecosystems.length - 1, sev: f.sev })); break;
      case "PageDown":   e.preventDefault(); move(0, 5); break;
      case "PageUp":     e.preventDefault(); move(0, -5); break;
      case "Enter":
      case " ":
        e.preventDefault();
        activate(ecosystems[focus.eco], SEVERITIES[focus.sev]);
        break;
    }
  };

  return (
    <Card>
      <Card.Header
        title="Risk Heatmap"
        subtitle="Vulnerability count by ecosystem × severity. Click a cell to filter the vulnerability list."
        actions={
          data && (
            <span className="aion-mono text-[11px]">
              {data.totalVulns} total vulns · generated just now
            </span>
          )
        }
      />
      <Card.Body>
        {loading || !data ? (
          <div className="grid h-72 place-items-center text-sm text-muted">
            Loading heatmap…
          </div>
        ) : (
          <div className="overflow-x-auto">
            <svg
              role="grid"
              aria-label="Risk heatmap: ecosystem columns, severity rows"
              aria-rowcount={SEVERITIES.length}
              aria-colcount={ecosystems.length}
              className="font-mono text-[10px]"
            >
              {/* Column headers (ecosystems) */}
              <g>
                {ecosystems.map((eco, i) => (
                  <text
                    key={eco}
                    x={CELL_X(i) + CELL_W / 2}
                    y={HEADER_Y}
                    textAnchor="middle"
                    className="fill-muted"
                  >
                    {eco}
                  </text>
                ))}
              </g>

              {/* Rows */}
              {SEVERITIES.map((sev, sIdx) => (
                <g
                  key={sev}
                  role="row"
                  aria-rowindex={sIdx + 1}
                >
                  {/* Row label */}
                  <text
                    x={LABEL_X}
                    y={CELL_Y(sIdx) + CELL_H / 2 + 3}
                    textAnchor="end"
                    className={clsx(
                      "fill-muted",
                      focus.sev === sIdx && "fill-text"
                    )}
                  >
                    {titleCase(sev)}
                  </text>

                  {ecosystems.map((eco, eIdx) => {
                    const cell = cellMap.get(`${eco}:${sev}`);
                    const count = cell?.count ?? 0;
                    const isFocused = focus.eco === eIdx && focus.sev === sIdx;
                    return (
                      <g
                        key={`${eco}:${sev}`}
                        ref={(el) => {
                          if (!cellRefs.current[sIdx]) cellRefs.current[sIdx] = [];
                          cellRefs.current[sIdx][eIdx] = el;
                        }}
                        role="gridcell"
                        tabIndex={isFocused ? 0 : -1}
                        aria-label={`${eco} ${sev}: ${count} vulnerabilities`}
                        aria-selected={isFocused}
                        onKeyDown={onKey}
                        onClick={() => activate(eco, sev)}
                        onFocus={() => setFocus({ eco: eIdx, sev: sIdx })}
                        style={{ cursor: "pointer", outline: "none" }}
                        className="focus:outline-none"
                      >
                        <rect
                          x={CELL_X(eIdx)}
                          y={CELL_Y(sIdx)}
                          width={CELL_W}
                          height={CELL_H}
                          rx={3}
                          fill={cellColor(count, max, sev)}
                          stroke={isFocused ? "hsl(var(--accent))" : "hsl(var(--border))"}
                          strokeWidth={isFocused ? 2 : 1}
                        />
                        <text
                          x={CELL_X(eIdx) + CELL_W / 2}
                          y={CELL_Y(sIdx) + CELL_H / 2 + 3}
                          textAnchor="middle"
                          className="pointer-events-none select-none"
                          fill={textColor()}
                        >
                          {count}
                        </text>
                      </g>
                    );
                  })}
                </g>
              ))}
            </svg>
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

// -------------------------------------------------------------------------
// Layout constants and helpers
// -------------------------------------------------------------------------

const LABEL_W   = 72;
const HEADER_H  = 24;
const CELL_W    = 88;
const CELL_H    = 44;
const PADDING_X = 8;
const PADDING_Y = 8;

const LABEL_X = LABEL_W;
const HEADER_Y = HEADER_H;

const CELL_X = (i: number) => LABEL_W + PADDING_X + i * CELL_W;
const CELL_Y = (i: number) => HEADER_H + PADDING_Y + i * CELL_H;

function clamp(n: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, n));
}

/** Map count + max + severity to a heat color. Green -> red. */
function cellColor(count: number, max: number, sev: Severity): string {
  if (count === 0) return "hsl(var(--surface-2))";
  const t = max > 0 ? Math.min(1, count / max) : 0;
  // Bias by severity: critical starts further along the gradient so
  // a low-count critical cell still reads as "red-ish".
  const bias: Record<Severity, number> = {
    critical: 0.55, high: 0.4, medium: 0.25, low: 0.15, info: 0.05,
  };
  const x = Math.min(1, t + bias[sev]);
  // Single linear gradient: green (140) -> red (0).
  const hue = Math.max(0, 140 - 140 * x);
  return `hsl(${hue.toFixed(0)} 78% 38%)`;
}

function textColor(): string {
  // Cell lightness is ~38%, so light text reads well.
  return "hsl(var(--text))";
}

// Silence unused-export warning; tCellColor was used by the previous
// text-color heuristic and is kept for future re-tuning.
void tCellColor;

/** Mirror of cellColor but returns lightness for contrast. */
function tCellColor(count: number, max: number, sev: Severity): number {
  if (count === 0) return 0;
  const t = max > 0 ? Math.min(1, count / max) : 0;
  const bias: Record<Severity, number> = {
    critical: 0.5, high: 0.4, medium: 0.3, low: 0.2, info: 0.1,
  };
  return Math.min(1, t + bias[sev]);
}
