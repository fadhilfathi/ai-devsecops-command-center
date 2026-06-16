import { useMemo, useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import type { TopologyGraph, TopologyNode, TopologyEdge } from "@/types/infrastructure";

const KIND_COLORS: Record<TopologyNode["kind"], string> = {
  cluster: "#7c3aed",
  namespace: "#0ea5e9",
  service: "#10b981",
  workload: "#f59e0b",
  pod: "#ef4444",
  ingress: "#6366f1",
  external: "#6b7280",
};

/**
 * Topology Viewer — simple SVG render of a topology graph
 * (application graph / service map / full topology graph).
 *
 * Layout: deterministic radial layout (root node at the
 * center). Sprint 5 will swap in dagre / elk.js.
 */
export function TopologyViewer() {
  const { data: graphs } = useFetch(api.topologyGraphs, { items: [], total: 0 });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const graph: TopologyGraph | undefined = useMemo(
    () => graphs.items[0] ?? { id: "default", tenantId: "—", name: "application", nodes: [], edges: [], generatedAt: new Date().toISOString() } as TopologyGraph,
    [graphs.items],
  );

  const positioned = useMemo(() => layoutRadial(graph.nodes, graph.edges), [graph]);
  const selected: TopologyNode | undefined = useMemo(
    () => graph.nodes.find((n) => n.id === selectedId),
    [graph.nodes, selectedId],
  );
  const selectedEdges: TopologyEdge[] = useMemo(
    () => graph.edges.filter((e) => e.source === selectedId || e.target === selectedId),
    [graph.edges, selectedId],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Topology Viewer"
        subtitle="Application graph — ingresses, services, and the workloads they select."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Topology" }]}
        actions={
          <Button size="sm" variant="secondary" onClick={() => setSelectedId(null)}>Clear selection</Button>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <Card.Header title={graph.name} subtitle={`${graph.nodes.length} nodes · ${graph.edges.length} edges`} />
          <Card.Body>
            <div className="aspect-[4/3] w-full overflow-hidden rounded-md border border-aion-border bg-aion-surface2">
              <svg viewBox="0 0 800 600" className="h-full w-full">
                {graph.edges.map((e) => {
                  const a = positioned.get(e.source);
                  const b = positioned.get(e.target);
                  if (!a || !b) return null;
                  return (
                    <g key={e.id}>
                      <line
                        x1={a.x} y1={a.y}
                        x2={b.x} y2={b.y}
                        stroke="#475569"
                        strokeWidth={Math.max(1, e.weight)}
                        strokeOpacity={0.6}
                      />
                      {e.label && (
                        <text
                          x={(a.x + b.x) / 2}
                          y={(a.y + b.y) / 2 - 4}
                          fontSize={9}
                          fill="#94a3b8"
                          textAnchor="middle"
                        >{e.label}</text>
                      )}
                    </g>
                  );
                })}
                {graph.nodes.map((n) => {
                  const p = positioned.get(n.id);
                  if (!p) return null;
                  return (
                    <g key={n.id} style={{ cursor: "pointer" }} onClick={() => setSelectedId(n.id)}>
                      <circle
                        cx={p.x} cy={p.y}
                        r={selectedId === n.id ? 18 : 14}
                        fill={KIND_COLORS[n.kind] ?? "#6b7280"}
                        stroke={selectedId === n.id ? "#fff" : "transparent"}
                        strokeWidth={2}
                      />
                      <text
                        x={p.x} y={p.y + 30}
                        fontSize={11}
                        fill="#e2e8f0"
                        textAnchor="middle"
                      >{n.label}</text>
                      <text
                        x={p.x} y={p.y + 44}
                        fontSize={9}
                        fill="#94a3b8"
                        textAnchor="middle"
                      >{n.kind}</text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </Card.Body>
        </Card>
        <Card>
          <Card.Header title="Selection" subtitle={selected ? selected.label : "Click a node to inspect it"} />
          <Card.Body>
            {selected ? (
              <div className="space-y-2 text-xs">
                <div><span className="text-aion-muted">Kind:</span> {selected.kind}</div>
                <div><span className="text-aion-muted">Namespace:</span> {selected.namespace ?? "—"}</div>
                <div><span className="text-aion-muted">Cluster:</span> {selected.clusterName ?? "—"}</div>
                <div><span className="text-aion-muted">Tags:</span> {selected.tags.join(", ") || "—"}</div>
                <div>
                  <span className="text-aion-muted">Edges:</span> {selectedEdges.length}
                </div>
                {selectedEdges.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {selectedEdges.map((e) => (
                      <li key={e.id} className="rounded border border-aion-border p-1 text-[11px]">
                        <Badge variant="neutral">{e.kind}</Badge>{" "}
                        {e.source} → {e.target}
                        {e.label && <div className="text-aion-muted">{e.label}</div>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ) : (
              <div className="text-xs text-aion-muted">No node selected.</div>
            )}
          </Card.Body>
        </Card>
      </div>
    </div>
  );
}

function layoutRadial(nodes: TopologyNode[], _edges: TopologyEdge[]): Map<string, { x: number; y: number }> {
  // Simple concentric layout: ingress → center; services → ring 1;
  // workloads → ring 2; everything else → ring 3. Deterministic.
  const result = new Map<string, { x: number; y: number }>();
  const cx = 400;
  const cy = 300;
  const rings: Record<TopologyNode["kind"], number> = {
    ingress: 0,
    service: 1,
    workload: 2,
    pod: 3,
    namespace: 3,
    cluster: 3,
    external: 3,
  };
  const byRing = new Map<number, TopologyNode[]>();
  for (const n of nodes) {
    const r = rings[n.kind];
    const arr = byRing.get(r) ?? [];
    arr.push(n);
    byRing.set(r, arr);
  }
  for (const [r, arr] of byRing.entries()) {
    if (r === 0) {
      for (const n of arr) result.set(n.id, { x: cx, y: cy });
      continue;
    }
    const radius = 80 + r * 70;
    const step = (Math.PI * 2) / Math.max(1, arr.length);
    arr.forEach((n, i) => {
      result.set(n.id, {
        x: cx + Math.cos(i * step) * radius,
        y: cy + Math.sin(i * step) * radius,
      });
    });
  }
  return result;
}
