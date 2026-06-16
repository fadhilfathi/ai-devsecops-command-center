/**
 * Cluster repository — in-memory tenant-scoped cluster registry.
 *
 * Sprint 4: the kubernetes service maintains the *set of onboarded
 * clusters* for each tenant. The cluster record is the metadata
 * AICC needs to dispatch inventory calls to the right provider —
 * actual inventory data is fetched per-request from the provider.
 */
import { randomUUID } from 'node:crypto';
import type { UUID } from '@aicc/shared';
import type { Cluster, ClusterProvider } from '@aicc/models';

export interface CreateClusterInput {
  tenantId: UUID;
  name: string;
  server: string;
  provider: ClusterProvider;
  k8sVersion?: string;
  region?: string;
  environment?: 'prod' | 'staging' | 'dev' | 'sandbox';
  labels?: Record<string, string>;
  token?: string;
  caBundle?: string;
  insecureSkipVerify?: boolean;
}

export interface ClusterRepository {
  list(tenantId: UUID): Promise<Cluster[]>;
  findById(id: UUID, tenantId: UUID): Promise<Cluster | undefined>;
  create(input: CreateClusterInput): Promise<Cluster>;
  remove(id: UUID, tenantId: UUID): Promise<boolean>;
  /** Returns the provider id, or `undefined` if not configured. */
  getProviderIdForCluster(id: UUID, tenantId: UUID): Promise<string | undefined>;
}

interface StoredCluster extends Cluster {
  /** Encrypted-at-rest in production; plain here for the Sprint 4 stub. */
  _credentials?: { token?: string; caBundle?: string; insecureSkipVerify?: boolean };
}

function newId(): UUID {
  return randomUUID();
}

export function buildClusterRepository(): ClusterRepository {
  const store = new Map<UUID, StoredCluster>();
  return {
    async list(tenantId) {
      return Array.from(store.values()).filter((c) => c.tenantId === tenantId);
    },
    async findById(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      return c;
    },
    async create(input) {
      const now = new Date().toISOString();
      const cluster: StoredCluster = {
        id: newId(),
        tenantId: input.tenantId,
        name: input.name,
        server: input.server,
        provider: input.provider,
        k8sVersion: input.k8sVersion,
        region: input.region,
        environment: input.environment ?? 'dev',
        phase: 'active',
        nodeCount: 0,
        readyNodes: 0,
        totalCpuCores: 0,
        totalMemoryBytes: 0,
        nodes: [],
        labels: input.labels ?? {},
        createdAt: now,
        updatedAt: now,
        _credentials: {
          token: input.token,
          caBundle: input.caBundle,
          insecureSkipVerify: input.insecureSkipVerify,
        },
      };
      store.set(cluster.id, cluster);
      return cluster;
    },
    async remove(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return false;
      store.delete(id);
      return true;
    },
    async getProviderIdForCluster(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      // Sprint 4: only the fixture provider is wired; the live
      // provider is reserved for Sprint 5.
      return 'fixture';
    },
  };
}
