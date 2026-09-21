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
import type { Queryable } from '@aicc/shared/db';
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

/** Connection details needed to build a live Kubernetes API client. */
export interface ClusterConnection {
  server: string;
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
  /** Returns connection details for the live provider, or `undefined` if unavailable. */
  getConnection(id: UUID, tenantId: UUID): Promise<ClusterConnection | undefined>;
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
      // `ClusterProvider` enumerates cloud vendors (eks/gke/aks/...);
      // any onboarded cluster is routed to the live provider unless
      // explicitly marked 'fixture'.
      return (c.provider as string) === 'fixture' ? 'fixture' : 'live';
    },
    async getConnection(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId || !c.server) return undefined;
      return {
        server: c.server,
        token: c._credentials?.token,
        caBundle: c._credentials?.caBundle,
        insecureSkipVerify: c._credentials?.insecureSkipVerify,
      };
    },
  };
}

// Credential columns are only selected by getConnection().
interface ClusterRow {
  id: UUID;
  tenant_id: UUID;
  name: string;
  provider: ClusterProvider;
  environment: 'prod' | 'staging' | 'dev' | 'sandbox';
  labels: Record<string, string>;
  server: string | null;
  token: string | null;
  ca_bundle: string | null;
  insecure_skip_verify: boolean;
  k8s_version: string | null;
  region: string | null;
  created_at: string;
  updated_at: string;
}

function rowToCluster(row: ClusterRow): Cluster {
  const labels = typeof row.labels === 'string' ? JSON.parse(row.labels) : row.labels;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    server: row.server ?? undefined,
    provider: row.provider,
    k8sVersion: row.k8s_version ?? undefined,
    region: row.region ?? undefined,
    environment: row.environment,
    phase: 'active',
    nodeCount: 0,
    readyNodes: 0,
    totalCpuCores: 0,
    totalMemoryBytes: 0,
    nodes: [],
    labels,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

/**
 * Postgres-backed cluster repository. Credentials (token/CA bundle) are
 * stored in plain columns for now — encryption-at-rest is tracked as a
 * follow-up ticket (see ADR-0010).
 */
export function buildPgClusterRepository(db: Queryable): ClusterRepository {
  return {
    async list(tenantId) {
      const { rows } = await db.query<ClusterRow>(
        `SELECT id, tenant_id, name, provider, environment, labels, server, insecure_skip_verify, k8s_version, region, created_at, updated_at FROM clusters WHERE tenant_id = $1 ORDER BY created_at ASC`,
        [tenantId],
      );
      return rows.map(rowToCluster);
    },
    async findById(id, tenantId) {
      const { rows } = await db.query<ClusterRow>(
        `SELECT id, tenant_id, name, provider, environment, labels, server, insecure_skip_verify, k8s_version, region, created_at, updated_at FROM clusters WHERE id = $1 AND tenant_id = $2`,
        [id, tenantId],
      );
      return rows[0] ? rowToCluster(rows[0]) : undefined;
    },
    async create(input) {
      const id = newId();
      const { rows } = await db.query<ClusterRow>(
        `INSERT INTO clusters
           (id, tenant_id, name, provider, environment, labels, server, token, ca_bundle,
            insecure_skip_verify, k8s_version, region)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING *`,
        [
          id,
          input.tenantId,
          input.name,
          input.provider,
          input.environment ?? 'dev',
          JSON.stringify(input.labels ?? {}),
          input.server,
          input.token ?? null,
          input.caBundle ?? null,
          input.insecureSkipVerify ?? false,
          input.k8sVersion ?? null,
          input.region ?? null,
        ],
      );
      return rowToCluster(rows[0]!);
    },
    async remove(id, tenantId) {
      const { rows } = await db.query(
        'DELETE FROM clusters WHERE id = $1 AND tenant_id = $2 RETURNING id',
        [id, tenantId],
      );
      return rows.length > 0;
    },
    async getProviderIdForCluster(id, tenantId) {
      const { rows } = await db.query<{ provider: ClusterProvider }>(
        'SELECT provider FROM clusters WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      const provider = rows[0]?.provider;
      if (!provider) return undefined;
      return (provider as string) === 'fixture' ? 'fixture' : 'live';
    },
    async getConnection(id, tenantId) {
      const { rows } = await db.query<ClusterRow>(
        'SELECT * FROM clusters WHERE id = $1 AND tenant_id = $2',
        [id, tenantId],
      );
      const row = rows[0];
      if (!row || !row.server) return undefined;
      return {
        server: row.server,
        token: row.token ?? undefined,
        caBundle: row.ca_bundle ?? undefined,
        insecureSkipVerify: row.insecure_skip_verify,
      };
    },
  };
}
