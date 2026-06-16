import type { Logger } from '@aicc/shared';
import type { Cluster, Namespace, Workload, Pod, Service, Deployment, StatefulSet, DaemonSet, Ingress } from '@aicc/models';
import { buildFixtureProvider, type KubernetesProvider, type ListOptions } from '../providers/index.js';

export interface InventorySnapshot {
  clusters: Cluster[]; namespaces: Namespace[]; workloads: Workload[]; pods: Pod[];
  services: Service[]; deployments: Deployment[]; statefulsets: StatefulSet[]; daemonsets: DaemonSet[]; ingresses: Ingress[];
}

export interface InventoryClient { fetch(tenantId: string, clusterId?: string): Promise<InventorySnapshot>; }

export function buildInventoryClient(deps: { logger: Logger }): InventoryClient {
  const provider: KubernetesProvider = buildFixtureProvider(deps.logger);
  return {
    async fetch(tenantId, clusterId) {
      const clusters = await provider.listClusters(tenantId);
      const target = clusterId ? clusters.filter((c) => c.id === clusterId) : clusters;
      const namespaces: Namespace[] = [];
      const workloads: Workload[] = [];
      const pods: Pod[] = [];
      const services: Service[] = [];
      const deployments: Deployment[] = [];
      const statefulsets: StatefulSet[] = [];
      const daemonsets: DaemonSet[] = [];
      const ingresses: Ingress[] = [];
      for (const cluster of target) {
        namespaces.push(...(await provider.listNamespaces(tenantId, cluster.id)));
        const opts: ListOptions = { clusterId: cluster.id };
        const [d, s, da, p, sv, ing] = await Promise.all([
          provider.listDeployments(tenantId, opts),
          provider.listStatefulSets(tenantId, opts),
          provider.listDaemonSets(tenantId, opts),
          provider.listPods(tenantId, opts),
          provider.listServices(tenantId, opts),
          provider.listIngresses(tenantId, opts),
        ]);
        deployments.push(...d);
        statefulsets.push(...s);
        daemonsets.push(...da);
        pods.push(...p);
        services.push(...sv);
        ingresses.push(...ing);
        workloads.push(...d, ...s, ...da);
      }
      return { clusters: target, namespaces, workloads, pods, services, deployments, statefulsets, daemonsets, ingresses };
    },
  };
}
