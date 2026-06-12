import type { ComplianceControl, ComplianceFramework, UUID } from '@aicc/shared';

export interface CreateControlInput {
  tenantId: UUID;
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  evidenceRefs?: string[];
}

export interface ControlRepository {
  list(tenantId: UUID, opts?: { framework?: ComplianceFramework }): Promise<ComplianceControl[]>;
  findById(id: UUID, tenantId: UUID): Promise<ComplianceControl | undefined>;
  create(input: CreateControlInput): Promise<ComplianceControl>;
  updateStatus(id: UUID, tenantId: UUID, status: ComplianceControl['status']): Promise<ComplianceControl | undefined>;
  addEvidence(id: UUID, tenantId: UUID, evidenceRef: string): Promise<ComplianceControl | undefined>;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

export function buildControlRepository(): ControlRepository {
  const store = new Map<UUID, ComplianceControl>();
  return {
    async list(tenantId, opts) {
      return Array.from(store.values()).filter(
        (c) => c.tenantId === tenantId && (!opts?.framework || c.framework === opts.framework),
      );
    },
    async findById(id, tenantId) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      return c;
    },
    async create(input) {
      const now = new Date().toISOString();
      const control: ComplianceControl = {
        id: newId(),
        tenantId: input.tenantId,
        framework: input.framework,
        controlId: input.controlId,
        title: input.title,
        description: input.description,
        status: 'manual_review',
        evidenceRefs: input.evidenceRefs ?? [],
        createdAt: now,
        updatedAt: now,
      };
      store.set(control.id, control);
      return control;
    },
    async updateStatus(id, tenantId, status) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      const next: ComplianceControl = { ...c, status, updatedAt: new Date().toISOString() };
      store.set(id, next);
      return next;
    },
    async addEvidence(id, tenantId, evidenceRef) {
      const c = store.get(id);
      if (!c || c.tenantId !== tenantId) return undefined;
      if (c.evidenceRefs.includes(evidenceRef)) return c;
      const next: ComplianceControl = {
        ...c,
        evidenceRefs: [...c.evidenceRefs, evidenceRef],
        updatedAt: new Date().toISOString(),
      };
      store.set(id, next);
      return next;
    },
  };
}
