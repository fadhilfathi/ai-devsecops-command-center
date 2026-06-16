/**
 * Inventory client.
 *
 * Abstracts how the k8s-health service reads cluster inventory.
 * In Sprint 4 we use the same in-process fixture provider as
 * the kubernetes-service. In Sprint 5 this client will be wired
 * to the kubernetes-service HTTP API.
 */
import { randomUUID } from 'node:crypto';
import type { Logger } from '@aicc/shared';
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
} from '@aicc/models';
import type {
  KubernetesProvider,
  ListOptions,
} from '../providers/kubernetes-provider.types.js';
import { buildFixtureProvider } from '../providers/fixture.provider.js';

export interface InventorySnapshot {
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

export interface InventoryClient {
  fetch(tenantId: string, clusterId?: string): Promise<InventorySnapshot>;
}

export interface InventoryClientDeps {
  logger: Logger;
}

export function buildInventoryClient(deps: InventoryClientDeps): InventoryClient {
  const provider: KubernetesProvider = buildFixtureProvider(deps.logger);

  return {
    async fetch(tenantId, clusterId) {
      const clusters = await provider.listClusters(tenantId);
      const target = clusterId
        ? clusters.filter((c) => c.id === clusterId)
        : clusters;
      const ns: Namespace[] = [];
      const workloads: Workload[] = [];
      const pods: Pod[] = [];
      const services: Service[] = [];
      const deployments: Deployment[] = [];
      const statefulsets: StatefulSet[] = [];
      const daemonsets: DaemonSet[] = [];
      const ingresses: Ingress[] = [];

      for (const cluster of target) {
        const nsList = await provider.listNamespaces(tenantId, cluster.id);
        ns.push(...nsList);
        const opts: ListOptions = { clusterId: cluster.id };
        const [ds, ss, daemons, podList, svcList, ingList] = await Promise.all([
          provider.listDeployments(tenantId, opts),
          provider.listStatefulSets(tenantId, opts),
          provider.listDaemonSets(tenantId, opts),
          provider.listPods(tenantId, opts),
          provider.listServices(tenantId, opts),
          provider.listIngresses(tenantId, opts),
        ]);
        deployments.push(...ds);
        statefulsets.push(...ss);
        daemonsets.push(...daemons);
        pods.push(...podList);
        services.push(...svcList);
        ingresses.push(...ingList);
        const wl = [...ds, ...ss, ...daemons];
        workloads.push(...wl);
      }

      return {
        clusters: target,
        namespaces: ns,
        workloads,
        pods,
        services,
        deployments,
        statefulsets,
        daemonsets,
        ingresses,
      };
    },
  };
}

// Re-export for use by other services that may want to use the
// fixture provider directly (cost-intel, runtime-security, ...).
export { buildFixtureProvider } from '../providers/fixture.provider.js';
export { randomUUID };
