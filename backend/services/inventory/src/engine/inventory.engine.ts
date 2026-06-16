/**
 * Inventory Engine.
 *
 * Pure functions that turn a tenant inventory snapshot into:
 *   - a Unified Asset Catalog (Asset[] — one entry per cluster,
 *     namespace, service, deployment, statefulset, daemonset,
 *     ingress)
 *   - a Relationship Graph (Asset → Asset edges, e.g.
 *     Service.SELECTS → Workload)
 *   - a Dependency Graph (Asset → Asset, e.g. Workload.DEPENDS_ON
 *     → Service)
 *
 * The graph formats are returned as `{ nodes, edges }` so they
 * can be rendered directly by the topology viewer.
 */
import { randomUUID } from 'node:crypto';
import type {
  Cluster,
  Namespace,
  Workload,
  Pod,
  Service,
  Deployment,
  StatefulSet,
  DaemonSet,
  Ingress,
  TopologyNode,
  TopologyEdge,
  TopologyNodeKind,
  TopologyEdgeKind,
} from '@aicc/models';

export type AssetKind =
  | 'cluster'
  | 'namespace'
  | 'service'
  | 'deployment'
  | 'statefulset'
  | 'daemonset'
  | 'ingress'
  | 'workload'
  | 'pod';

export interface Asset {
  id: string;
  tenantId: string;
  kind: AssetKind;
  name: string;
  namespace?: string;
  clusterId: string;
  clusterName: string;
  labels: Record<string, string>;
  metadata: Record<string, unknown>;
}

export interface InventoryEngineInput {
  clusters: Cluster[];
  namespaces: Namespace[];
  workloads: Workload[];
  pods: Pod[];
  services: Service[];
  deployments: Deployment[];
  statefulsets: StatefulSet[];
  daemonsets: DaemonSet[];
  ingresses: Ingress[];
}

export interface InventoryEngine {
  catalog(input: InventoryEngineInput): Asset[];
  relationshipGraph(input: InventoryEngineInput): { nodes: TopologyNode[]; edges: TopologyEdge[] };
  dependencyGraph(input: InventoryEngineInput): { nodes: TopologyNode[]; edges: TopologyEdge[] };
  dependenciesFor(input: InventoryEngineInput, assetId: string): { nodes: TopologyNode[]; edges: TopologyEdge[] };
}

function toNodeKind(kind: AssetKind): TopologyNodeKind {
  switch (kind) {
    case 'cluster': return 'cluster';
    case 'namespace': return 'namespace';
    case 'service': return 'service';
    case 'ingress': return 'ingress';
    case 'pod': return 'pod';
    case 'deployment':
    case 'statefulset':
    case 'daemonset':
    case 'workload':
      return 'workload';
    default:
      return 'external';
  }
}

function makeNode(asset: Asset, riskScore = 0, position?: { x: number; y: number }): TopologyNode {
  return {
    id: asset.id,
    label: asset.name,
    kind: toNodeKind(asset.kind),
    namespace: asset.namespace,
    clusterId: asset.clusterId,
    clusterName: asset.clusterName,
    riskScore,
    tags: Object.entries(asset.labels).map(([k, v]) => `${k}=${v}`),
    position,
    metadata: asset.metadata,
  };
}

function makeEdge(
  source: string,
  target: string,
  kind: TopologyEdgeKind,
  label?: string,
  weight = 1.0,
): TopologyEdge {
  return { id: randomUUID(), source, target, kind, label, weight, metadata: {} };
}

export function buildInventoryEngine(): InventoryEngine {
  return {
    catalog(input) {
      const out: Asset[] = [];
      for (const c of input.clusters) {
        out.push({
          id: c.id, tenantId: c.tenantId, kind: 'cluster',
          name: c.name, clusterId: c.id, clusterName: c.name,
          labels: c.labels, metadata: { provider: c.provider, k8sVersion: c.k8sVersion, region: c.region, environment: c.environment },
        });
      }
      for (const n of input.namespaces) {
        out.push({
          id: n.id, tenantId: n.tenantId, kind: 'namespace',
          name: n.name, namespace: n.name, clusterId: n.clusterId, clusterName: n.clusterName,
          labels: n.labels, metadata: { phase: n.phase },
        });
      }
      for (const s of input.services) {
        out.push({
          id: s.id, tenantId: s.tenantId, kind: 'service',
          name: s.name, namespace: s.namespace, clusterId: s.clusterId, clusterName: s.clusterName,
          labels: s.labels, metadata: { type: s.type, clusterIp: s.clusterIp, ports: s.ports, fqdn: s.fqdn },
        });
      }
      for (const d of input.deployments) {
        out.push({
          id: d.id, tenantId: d.tenantId, kind: 'deployment',
          name: d.name, namespace: d.namespace, clusterId: d.clusterId, clusterName: d.clusterName,
          labels: d.labels, metadata: { image: d.image, replicas: d.replicas, rollout: d.rollout },
        });
      }
      for (const s of input.statefulsets) {
        out.push({
          id: s.id, tenantId: s.tenantId, kind: 'statefulset',
          name: s.name, namespace: s.namespace, clusterId: s.clusterId, clusterName: s.clusterName,
          labels: s.labels, metadata: { image: s.image, replicas: s.replicas },
        });
      }
      for (const d of input.daemonsets) {
        out.push({
          id: d.id, tenantId: d.tenantId, kind: 'daemonset',
          name: d.name, namespace: d.namespace, clusterId: d.clusterId, clusterName: d.clusterName,
          labels: d.labels, metadata: { image: d.image, replicas: d.replicas },
        });
      }
      for (const i of input.ingresses) {
        out.push({
          id: i.id, tenantId: i.tenantId, kind: 'ingress',
          name: i.name, namespace: i.namespace, clusterId: i.clusterId, clusterName: i.clusterName,
          labels: i.labels, metadata: { className: i.className, rules: i.rules, tls: i.tls },
        });
      }
      return out;
    },

    relationshipGraph(input) {
      const assets = this.catalog(input);
      const assetByKey = new Map<string, Asset>();
      for (const a of assets) assetByKey.set(`${a.kind}:${a.clusterId}:${a.namespace ?? ''}:${a.name}`, a);

      const nodes = assets.map((a) => makeNode(a));
      const edges: TopologyEdge[] = [];

      // Cluster contains Namespace.
      const nsByCluster = new Map<string, Namespace[]>();
      for (const n of input.namespaces) {
        const arr = nsByCluster.get(n.clusterId) ?? [];
        arr.push(n);
        nsByCluster.set(n.clusterId, arr);
      }
      for (const c of input.clusters) {
        for (const n of nsByCluster.get(c.id) ?? []) {
          const child = assetByKey.get(`namespace:${n.clusterId}:${n.name}:${n.name}`);
          if (child) edges.push(makeEdge(c.id, child.id, 'in_namespace'));
        }
      }
      // Service SELECTS Workload (via selector).
      const workloadsBySelector = new Map<string, Workload[]>();
      const key = (clusterId: string, namespace: string, label: string, value: string) =>
        `${clusterId}/${namespace}/${label}=${value}`;
      for (const w of input.workloads) {
        for (const [k, v] of Object.entries(w.labels)) {
          const arr = workloadsBySelector.get(key(w.clusterId, w.namespace, k, v)) ?? [];
          arr.push(w);
          workloadsBySelector.set(key(w.clusterId, w.namespace, k, v), arr);
        }
      }
      for (const s of input.services) {
        for (const [k, v] of Object.entries(s.selector)) {
          const matches = workloadsBySelector.get(key(s.clusterId, s.namespace, k, v)) ?? [];
          for (const w of matches) {
            const child = assetByKey.get(`${w.kind}:${w.clusterId}:${w.namespace}:${w.name}`);
            if (child) edges.push(makeEdge(s.id, child.id, 'selects'));
          }
        }
      }
      // Ingress ROUTES_TO Service.
      for (const ing of input.ingresses) {
        for (const rule of ing.rules) {
          const target = assetByKey.get(`service:${ing.clusterId}:${ing.namespace}:${rule.serviceName}`);
          if (target) {
            const port = typeof rule.servicePort === 'number' ? rule.servicePort : rule.servicePort;
            edges.push(makeEdge(ing.id, target.id, 'routes_to', `${rule.host ?? '*'}${rule.path}→:${port}`));
          }
        }
      }
      return { nodes, edges };
    },

    dependencyGraph(input) {
      const rel = this.relationshipGraph(input);
      // Dependency = who depends on whom. Reverse the edge direction
      // and rewrite the kind to `depends_on` (the topology viewer's
      // layout engine reads this as "if A depends_on B, draw A on
      // top of B").
      const nodes = rel.nodes;
      const edges: TopologyEdge[] = rel.edges.map((e) => ({
        ...makeEdge(e.target, e.source, 'depends_on', e.label, e.weight),
      }));
      return { nodes, edges };
    },

    dependenciesFor(input, assetId) {
      const g = this.dependencyGraph(input);
      const reachable = new Set<string>([assetId]);
      let changed = true;
      while (changed) {
        changed = false;
        for (const e of g.edges) {
          if (reachable.has(e.source) && !reachable.has(e.target)) {
            reachable.add(e.target);
            changed = true;
          }
        }
      }
      const nodes = g.nodes.filter((n) => reachable.has(n.id));
      const edges = g.edges.filter((e) => reachable.has(e.source) && reachable.has(e.target));
      return { nodes, edges };
    },
  };
}
