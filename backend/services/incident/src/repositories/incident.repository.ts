import type { Incident, IncidentSeverity, IncidentStatus, UUID } from '@aicc/shared';

export interface CreateIncidentInput {
  tenantId: UUID;
  title: string;
  description: string;
  severity: IncidentSeverity;
  relatedFindingIds?: UUID[];
  runbookId?: UUID;
  assigneeId?: UUID;
}

export interface IncidentRepository {
  list(tenantId: UUID, opts?: { status?: IncidentStatus; severity?: IncidentSeverity }): Promise<Incident[]>;
  findById(id: UUID, tenantId: UUID): Promise<Incident | undefined>;
  create(input: CreateIncidentInput): Promise<Incident>;
  update(id: UUID, tenantId: UUID, patch: Partial<Incident>): Promise<Incident | undefined>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

export function buildIncidentRepository(): IncidentRepository {
  const store = new Map<UUID, Incident>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (i) =>
          i.tenantId === tenantId &&
          (!opts?.status || i.status === opts.status) &&
          (!opts?.severity || i.severity === opts.severity),
      );
    },
    async findById(id, tenantId) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      return i;
    },
    async create(input) {
      const now = new Date().toISOString();
      const incident: Incident = {
        id: newId(),
        tenantId: input.tenantId,
        title: input.title,
        description: input.description,
        severity: input.severity,
        status: 'open',
        assigneeId: input.assigneeId,
        relatedFindingIds: input.relatedFindingIds ?? [],
        runbookId: input.runbookId,
        createdAt: now,
        updatedAt: now,
      };
      store.set(incident.id, incident);
      return incident;
    },
    async update(id, tenantId, patch) {
      const i = store.get(id);
      if (!i || i.tenantId !== tenantId) return undefined;
      const next: Incident = { ...i, ...patch, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
  };
}
