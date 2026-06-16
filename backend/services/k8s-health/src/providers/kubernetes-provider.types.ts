/**
 * Kubernetes provider types — shared shape used by the
 * fixture provider in Sprint 4 and the live (K8s API) provider
 * in Sprint 5.
 */
import type {
  Cluster,
  Namespace,
  Workload,
  Pod,
  Service,
  Ingress,
  Deployment,
  StatefulSet,
  DaemonSet,
} from '@aicc/models';

export interface ListOptions {
  clusterId: string;
  namespace?: string;
  labelSelector?: string;
}

export interface TestConnectionInput {
  server: string;
  token?: string;
  caBundle?: string;
  insecureSkipVerify?: boolean;
  name?: string;
}

export interface TestConnectionResult {
  ok: boolean;
  latencyMs: number;
  serverVersion?: string;
  platform?: string;
  message?: string;
}

export interface KubernetesProvider {
  readonly id: string;
  readonly name: string;
  readonly readOnly: boolean;
  testConnection(input: TestConnectionInput): Promise<TestConnectionResult>;
  listClusters(tenantId: string): Promise<Cluster[]>;
  listNamespaces(tenantId: string, clusterId: string): Promise<Namespace[]>;
  listWorkloads(tenantId: string, opts: ListOptions): Promise<Workload[]>;
  listPods(tenantId: string, opts: ListOptions): Promise<Pod[]>;
  listServices(tenantId: string, opts: ListOptions): Promise<Service[]>;
  listIngresses(tenantId: string, opts: ListOptions): Promise<Ingress[]>;
  listDeployments(tenantId: string, opts: ListOptions): Promise<Deployment[]>;
  listStatefulSets(tenantId: string, opts: ListOptions): Promise<StatefulSet[]>;
  listDaemonSets(tenantId: string, opts: ListOptions): Promise<DaemonSet[]>;
}
