import { useCallback, useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlowProvider,
  type Edge,
  type Node,
  type NodeProps,
} from "reactflow";
import "reactflow/dist/style.css";
import { X, ExternalLink } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { titleCase } from "@/lib/format";
import type { GraphData, GraphNode, Severity } from "@/types";

/**
 * DependencyGraph — force-directed graph of SBOM components.
 *
 * Sprint 2 / S2.6 visualization #4. Consumes
 * `GET /api/security/graph/{sbomId}` (S2.5). Lazy-loaded by
 * `routes/Graph.tsx` to keep `reactflow` out of the initial bundle.
 *
 * Interaction:
 *  - Pan / zoom (built-in via `reactflow`).
 *  - Click a node to open the side panel.
 *  - Tab moves through nodes; Enter opens the panel.
 *  - MiniMap in the bottom-right for orientation.
 *
 * Layout: `reactflow` does not ship a force layout in v11. We use
 * `dagre`-style hierarchical grouping by depth as a deterministic
 * pre-layout. Sprint 3 candidate: swap in a real d3-force simulation.
 */
export function DependencyGraph({ sbomId }: { sbomId: string }) {
  return (
    <ReactFlowProvider>
      <DependencyGraphInner sbomId={sbomId} />
    </ReactFlowProvider>
  );
}

function DependencyGraphInner({ sbomId }: { sbomId: string }) {
  const { data, loading } = useFetch(() => api.graphData(sbomId), [sbomId]);
  const [selected, setSelected] = useState<GraphNode | null>(null);

  // Build reactflow nodes/edges with a depth-based hierarchical layout.
  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    return layoutByDepth(data);
  }, [data]);

  // Map node id -> GraphNode for quick lookup when a side-panel key changes.
  const byId = useMemo(() => {
    const m = new Map<string, GraphNode>();
    (data?.nodes ?? []).forEach((n) => m.set(n.id, n));
    return m;
  }, [data]);

  const onNodeClick = useCallback(
    (_e: React.MouseEvent, node: Node) => {
      const gn = byId.get(node.id);
      if (gn) setSelected(gn);
    },
    [byId]
  );

  // Close side panel on Escape.
  useEffect(() => {
    if (!selected) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selected]);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
      <Card className="overflow-hidden">
        <Card.Header
          title="Dependency Graph"
          subtitle="Components and their direct / transitive dependencies. Red border = has open vulnerabilities."
          actions={
            <span className="aion-mono text-[11px]">
              {data ? `${data.nodes.length} nodes · ${data.edges.length} edges` : "…"}
            </span>
          }
        />
        <div className="h-[640px] bg-bg">
          {loading || !data ? (
            <div className="grid h-full place-items-center text-sm text-muted">
              Loading graph…
            </div>
          ) : nodes.length === 0 ? (
            <div className="grid h-full place-items-center text-sm text-muted">
              No components to graph.
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={NODE_TYPES}
              onNodeClick={onNodeClick}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              proOptions={{ hideAttribution: true }}
              minZoom={0.2}
              maxZoom={2.5}
            >
              <Background gap={24} size={1} color="hsl(var(--border))" />
              <Controls position="bottom-right" showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                nodeColor={(n) => {
                  const gn = byId.get(n.id);
                  if (!gn || !gn.highestSeverity) return "hsl(var(--surface-2))";
                  return SEV_COLOR[gn.highestSeverity];
                }}
                maskColor="hsl(var(--bg) / 0.7)"
                style={{
                  background: "hsl(var(--surface))",
                  border: "1px solid hsl(var(--border))",
                }}
              />
            </ReactFlow>
          )}
        </div>
      </Card>

      {/* Side panel */}
      {selected ? (
        <ComponentPanel node={selected} onClose={() => setSelected(null)} />
      ) : (
        <Card>
          <Card.Header title="Component details" />
          <Card.Body>
            <p className="text-sm text-muted">
              Click any node in the graph to see its details, dependencies,
              and vulnerability status.
            </p>
            <div className="mt-4 aion-mono text-[11px]">
              <div>Pan: drag the background</div>
              <div>Zoom: scroll or pinch</div>
              <div>Select: click or Tab + Enter</div>
              <div>Close panel: Esc</div>
            </div>
          </Card.Body>
        </Card>
      )}
    </div>
  );
}

function ComponentPanel({
  node,
  onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}) {
  return (
    <Card>
      <Card.Header
        title={node.label}
        actions={
          <button
            type="button"
            onClick={onClose}
            aria-label="Close component details"
            className="rounded p-1 text-muted hover:bg-surface-2 hover:text-text"
          >
            <X className="h-4 w-4" />
          </button>
        }
        subtitle={
          <span className="aion-mono">
            {node.ecosystem} · v{node.version} · depth {node.depth}
          </span>
        }
      />
      <Card.Body className="space-y-3 text-sm">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted">Status</div>
          {node.highestSeverity ? (
            <div className="mt-1">
              <Badge severity={node.highestSeverity}>
                {node.vulnCount} {titleCase(node.highestSeverity)} vuln
                {node.vulnCount === 1 ? "" : "s"}
              </Badge>
            </div>
          ) : (
            <Badge variant="ok" className="mt-1">
              No known vulnerabilities
            </Badge>
          )}
        </div>

        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted">Component ID</div>
          <div className="aion-mono mt-1 break-all text-text">{node.id}</div>
        </div>

        <div className="flex gap-2">
          <Button size="sm" variant="secondary">
            <ExternalLink className="h-3.5 w-3.5" /> Open in SBOM
          </Button>
          <Button size="sm" variant="ghost">
            View vulnerabilities
          </Button>
        </div>
      </Card.Body>
    </Card>
  );
}

// -------------------------------------------------------------------------
// Custom node + layout
// -------------------------------------------------------------------------

const SEV_COLOR: Record<Severity, string> = {
  critical: "hsl(0 84% 60%)",
  high:     "hsl(20 90% 55%)",
  medium:   "hsl(38 92% 50%)",
  low:      "hsl(199 89% 60%)",
  info:     "hsl(215 14% 60%)",
};

function SbomNode({ data }: NodeProps<{ node: GraphNode }>) {
  const n = data.node;
  const sev = n.highestSeverity;
  return (
    <div
      tabIndex={0}
      role="button"
      aria-label={`${n.label}, ${n.ecosystem} ${n.version}${
        sev ? `, ${n.vulnCount} ${sev} vulnerabilities` : ", no vulnerabilities"
      }`}
      className="rounded-md border-2 bg-surface px-2 py-1.5 text-left shadow-sm hover:border-accent/60"
      style={{
        borderColor: sev ? SEV_COLOR[sev] : "hsl(var(--border))",
        minWidth: 140,
      }}
    >
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div className="flex items-center gap-2">
        <span className="aion-mono text-[10px] uppercase text-muted">
          {n.ecosystem}
        </span>
        {sev && (
          <span
            aria-hidden="true"
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: SEV_COLOR[sev] }}
          />
        )}
      </div>
      <div className="truncate text-xs font-medium text-text">{n.label}</div>
      <div className="aion-mono text-[10px] text-muted">v{n.version}</div>
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
}

const handleStyle = {
  width: 6,
  height: 6,
  background: "hsl(var(--muted))",
  border: "1px solid hsl(var(--border))",
};

const NODE_TYPES = { sbom: SbomNode };

/** Deterministic depth-based layout: column per depth, evenly spaced. */
function layoutByDepth(data: GraphData): { nodes: Node[]; edges: Edge[] } {
  const byDepth = new Map<number, GraphNode[]>();
  data.nodes.forEach((n) => {
    const arr = byDepth.get(n.depth) ?? [];
    arr.push(n);
    byDepth.set(n.depth, arr);
  });
  const COL_W = 220;
  const ROW_H = 80;
  const nodes: Node[] = [];
  for (const [depth, list] of [...byDepth.entries()].sort((a, b) => a[0] - b[0])) {
    list.forEach((n, i) => {
      nodes.push({
        id: n.id,
        type: "sbom",
        position: { x: depth * COL_W, y: i * ROW_H - (list.length * ROW_H) / 2 },
        data: { node: n },
        draggable: true,
      });
    });
  }
  const edges: Edge[] = data.edges.map((e) => ({
    id: `${e.source}->${e.target}`,
    source: e.source,
    target: e.target,
    type: "smoothstep",
    animated: false,
    style: { stroke: "hsl(var(--muted))", strokeWidth: 1, opacity: 0.6 },
  }));
  return { nodes, edges };
}
