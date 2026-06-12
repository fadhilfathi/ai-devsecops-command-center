import { Line, LineChart, ResponsiveContainer, YAxis } from "recharts";

/**
 * Sparkline — minimal, axis-free trend line.
 *
 * Used by the SecurityScore sub-metric tiles. Renders the trend only;
 * numeric value lives next to it. Pass `color` as a CSS color (HSL
 * tokens or any other valid value).
 */
export function Sparkline({
  data,
  color = "hsl(var(--accent))",
  height = 28,
  ariaLabel,
}: {
  data: number[];
  color?: string;
  height?: number;
  ariaLabel?: string;
}) {
  if (data.length === 0) {
    return <div className="h-7" aria-hidden="true" />;
  }
  const series = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={series} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
        <YAxis hide domain={["dataMin", "dataMax"]} />
        <Line
          type="monotone"
          dataKey="v"
          stroke={color}
          strokeWidth={1.5}
          dot={false}
          isAnimationActive={false}
        />
        {ariaLabel && <title>{ariaLabel}</title>}
      </LineChart>
    </ResponsiveContainer>
  );
}
