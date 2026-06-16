/**
 * Topology Engine.
 *
 * Pure functions that turn an inventory snapshot into the three
 * pre-computed views (Service Map, Application Graph, Topology
 * Graph) plus a per-namespace view.
 *
 * The engine is intentionally simple — the heavy lifting
 * (cross-namespace Service FQDN resolution, network-policy
 * inference, ... ) is reserved for Sprint 5. Sprint 4 covers:
 *
 *   1. Service Map
 *      Nodes: services + workloads they select
 *      Edges: service.SELECTS → workload
 *
 *   2. Application Graph
 *      Nodes: ingresses + services + workloads
 *      Edges: ingress.ROUTES_TO → service
 *             service.SELECTS → workload
 *
 *   3. Topology Graph
 *      Nodes: cluster, namespace, ingress, service, workload
 *      Edges: cluster→namespace, namespace→workload, namespace→service,
 *             namespace→ingress, ingress→service, service→workload
 *
 *   4. Per-namespace view
 *      Filtered subgraph of (3) by namespace name.
 *
 *   5. Namespace relationships
 *      Edges between namespaces derived from ingress rules that
 *      target a service in another namespace.
 */
import { randomUUID } from 'node:crypto';
import type {
  Cluster, Namespace, Workload, Pod, Service, Ingress,
  Deployment, StatefulSet, DaemonSet,
  TopologyGraph, TopologyNode, TopologyEdge,
  TopologyNodeKind, TopologyEdgeKind,
} from '@aicc/models';

export interface TopologyEngineInput {
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

export interface TopologyEngine {
  serviceMap(input: TopologyEngineInput, name: string, clusterId?: string): TopologyGraph;
  applicationGraph(input: TopologyEngineInput, name: string, clusterId?: string): TopologyGraph;
  fullGraph(input: TopologyEngineInput, name: string, clusterId?: string): TopologyGraph;
  namespaceView(input: TopologyEngineInput, namespace: string, name: string, clusterId?: string): TopologyGraph;
  namespaceRelationships(input: TopologyEngineInput, clusterId?: string): { items: TopologyEdge[]; total: number };
}

function nodeKindFor(kind: 'cluster' | 'namespace' | 'service' | 'workload' | 'ingress' | 'pod'): TopologyNodeKind {
  return kind;
}

function makeNode(
  id: string, label: string, kind: TopologyNodeKind,
  namespace: string | undefined, clusterId: string | undefined, clusterName: string | undefined,
  tags: string[] = [],
  riskScore = 0,
): TopologyNode {
  return {
    id, label, kind, namespace, clusterId, clusterName,
    tags, riskScore, metadata: {},
  };
}

function makeEdge(source: string, target: string, kind: TopologyEdgeKind, label?: string, weight = 1.0): TopologyEdge {
  return { id: randomUUID(), source, target, kind, label, weight, metadata: {} };
}

function wrapGraph(
  tenantId: string, name: string, clusterId: string | undefined,
  nodes: TopologyNode[], edges: TopologyEdge[],
): TopologyGraph {
  return {
    id: randomUUID(),
    tenantId,
    name,
    clusterId,
    group: clusterId ? `cluster:${clusterId}` : 'tenant',
    nodes,
    edges,
    generatedAt: new Date().toISOString(),
  };
}

export function buildTopologyEngine(): TopologyEngine {
  return {
    serviceMap(input, name, clusterId) {
      const nodes: TopologyNode[] = [];
      const edges: TopologyEdge[] = [];
      const serviceKey = (s: Service) => `${s.clusterId}/${s.namespace}/${s.name}`;
      const workloadKey = (w: Workload) => `${w.clusterId}/${w.namespace}/${w.name}/${w.kind}`;
      const bySelector = new Map<string, Workload[]>();
      const sKey = (c: string, n: string, k: string, v: string) => `${c}/${n}/${k}=${v}`;
      for (const w of input.workloads) {
        for (const [k, v] of Object.entries(w.labels)) {
          const arr = bySelector.get(sKey(w.clusterId, w.namespace, k, v)) ?? [];
          arr.push(w);
          bySelector.set(sKey(w.clusterId, w.namespace, k, v), arr);
        }
      }
      for (const svc of input.services) {
        if (clusterId && svc.clusterId !== clusterId) continue;
        nodes.push(makeNode(svc.id, svc.name, 'service', svc.namespace, svc.clusterId, svc.clusterName, Object.entries(svc.selector).map(([k, v]) => `${k}=${v}`)));
        for (const [k, v] of Object.entries(svc.selector)) {
          const matches = bySelector.get(sKey(svc.clusterId, svc.namespace, k, v)) ?? [];
          for (const w of matches) {
            const wk = workloadKey(w);
            if (!nodes.find((n) => n.id === w.id)) {
              nodes.push(makeNode(w.id, w.name, 'workload', w.namespace, w.clusterId, w.clusterName, [wk]));
            }
            edges.push(makeEdge(svc.id, w.id, 'selects', `${k}=${v}`));
          }
        }
      }
      return wrapGraph(input.clusters[0]?.tenantId ?? '', name, clusterId, nodes, edges);
    },

    applicationGraph(input, name, clusterId) {
      const serviceMap = this.serviceMap(input, `${name} (services)`, clusterId);
      const nodes = [...serviceMap.nodes];
      const edges = [...serviceMap.edges];
      for (const ing of input.ingresses) {
        if (clusterId && ing.clusterId !== clusterId) continue;
        nodes.push(makeNode(ing.id, ing.name, 'ingress', ing.namespace, ing.clusterId, ing.clusterName, [`class=${ing.className}`]));
        for (const rule of ing.rules) {
          const target = input.services.find(
            (s) => s.clusterId === ing.clusterId && s.namespace === ing.namespace && s.name === rule.serviceName,
          );
          if (!target) continue;
          if (!nodes.find((n) => n.id === target.id)) {
            nodes.push(makeNode(target.id, target.name, 'service', target.namespace, target.clusterId, target.clusterName));
          }
          const port = typeof rule.servicePort === 'number' ? rule.servicePort : rule.servicePort;
          edges.push(makeEdge(ing.id, target.id, 'routes_to', `${rule.host ?? '*'}${rule.path}→:${port}`));
        }
      }
      return wrapGraph(input.clusters[0]?.tenantId ?? '', name, clusterId, nodes, edges);
    },

    fullGraph(input, name, clusterId) {
      const app = this.applicationGraph(input, `${name} (full)`, clusterId);
      const nodes = [...app.nodes];
      const edges = [...app.edges];
      // Add cluster and namespace nodes and edges.
      for (const c of input.clusters) {
        if (clusterId && c.id !== clusterId) continue;
        if (!nodes.find((n) => n.id === c.id)) {
          nodes.push(makeNode(c.id, c.name, 'cluster', undefined, c.id, c.name, [`provider=${c.provider}`]));
        }
      }
      for (const ns of input.namespaces) {
        if (clusterId && ns.clusterId !== clusterId) continue;
        const id = `ns:${ns.clusterId}:${ns.name}`;
        if (!nodes.find((n) => n.id === id)) {
          nodes.push(makeNode(id, ns.name, 'namespace', ns.name, ns.clusterId, ns.clusterName));
        }
        edges.push(makeEdge(ns.clusterId, id, 'in_namespace'));
        for (const n of nodes) {
          if (n.kind === 'workload' || n.kind === 'service' || n.kind === 'ingress') {
            if (n.clusterId === ns.clusterId && n.namespace === ns.name) {
              edges.push(makeEdge(id, n.id, 'in_namespace'));
            }
          }
        }
      }
      return wrapGraph(input.clusters[0]?.tenantId ?? '', name, clusterId, nodes, edges);
    },

    namespaceView(input, namespace, name, clusterId) {
      const full = this.fullGraph(input, name, clusterId);
      const ids = new Set<string>();
      for (const n of full.nodes) {
        if (n.namespace === namespace || n.label === namespace) ids.add(n.id);
      }
      const nodes = full.nodes.filter((n) => ids.has(n.id));
      const edges = full.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
      return wrapGraph(input.clusters[0]?.tenantId ?? '', name, clusterId, nodes, edges);
    },

    namespaceRelationships(input, clusterId) {
      const items: TopologyEdge[] = [];
      for (const ing of input.ingresses) {
        if (clusterId && ing.clusterId !== clusterId) continue;
        for (const rule of ing.rules) {
          const target = input.services.find(
            (s) => s.clusterId === ing.clusterId && s.name === rule.serviceName,
          );
          if (!target) continue;
          if (target.namespace === ing.namespace) continue;
          const fromId = `ns:${ing.clusterId}:${ing.namespace}`;
          const toId = `ns:${ing.clusterId}:${target.namespace}`;
          items.push(makeEdge(fromId, toId, 'routes_to', `ingress=${ing.name}→${target.name}`));
        }
      }
      return { items, total: items.length };
    },
  };
}

// re-export types used internally for the engine signature.
export type { TopologyNode, TopologyEdge, TopologyGraph };
