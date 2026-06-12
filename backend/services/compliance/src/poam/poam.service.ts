// POA&M service
//
// The service implements:
//   - Auto-creation from mapping-engine tuples (deduplicated).
//   - Manual creation via POST /poam.
//   - List and get with filters.
//   - Status transitions.
//   - Overdue scanning (called by the scheduler).
//
// The service is the single point that emits POA&M-related events to
// the bus. Other code (routes, schedulers) call into it; it does the
// persistence + event emission in a consistent order.

import type { EventEnvelope, EventBus } from '@aicc/shared/events';
import { EventTypes, type Severity } from '@aicc/shared/events';
import {
  POAM_SLA_DAYS,
  type CreatePoamInput,
  type CreatePoamResult,
  type ListPoamFilter,
  type PoamItem,
  type PoamSeverity,
  type PoamStatus,
} from './poam.types.js';
import type { PoamRepository } from './poam.repository.js';
import type { ControlVulnTuple } from '../control-mapper/index.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface PoamServiceDeps {
  repo: PoamRepository;
  bus: EventBus;
  now?: () => Date;
}

export class PoamService {
  private readonly repo: PoamRepository;
  private readonly bus: EventBus;
  private readonly now: () => Date;

  constructor(deps: PoamServiceDeps) {
    this.repo = deps.repo;
    this.bus = deps.bus;
    this.now = deps.now ?? (() => new Date());
  }

  // -------------------------------------------------------------------------
  // Auto-creation
  // -------------------------------------------------------------------------

  /**
   * Create POA&M items for a batch of (controlId, vulnId) tuples. Each
   * tuple is deduplicated against any existing open POA&M for the same
   * (tenantId, controlId, vulnId) pair. Newly created items emit a
   * `compliance.poam.created` event.
   *
   * Returns the list of newly created POA&M items (excluding dedup'd).
   */
  async createFromTuples(
    tenantId: string,
    tuples: ControlVulnTuple[],
  ): Promise<PoamItem[]> {
    const created: PoamItem[] = [];
    for (const t of tuples) {
      const result = await this.createFromTuple(tenantId, t);
      if (!result.deduplicated) created.push(result.poam);
    }
    return created;
  }

  /** Create a POA&M from a single (controlId, vulnId) tuple. Deduplicates. */
  async createFromTuple(
    tenantId: string,
    tuple: ControlVulnTuple,
  ): Promise<CreatePoamResult> {
    const existing = await this.repo.findOpenForControlVuln(
      tenantId,
      tuple.controlId,
      tuple.vulnId,
    );
    if (existing) {
      return { poam: existing, deduplicated: true };
    }

    const severity = mapSeverity(tuple.severity);
    const slaDays = tuple.slaDays ?? POAM_SLA_DAYS[severity];
    const now = this.now();
    const dueAt = new Date(now.getTime() + slaDays * DAY_MS).toISOString();
    const poam: PoamItem = {
      poamId: crypto.randomUUID(),
      tenantId,
      controlId: tuple.controlId,
      framework: tuple.framework,
      vulnId: tuple.vulnId,
      ruleId: tuple.ruleId,
      title: `Remediate ${tuple.controlId} violation (${severity})`,
      description: `Auto-created from rule ${tuple.ruleId}. Vuln ${tuple.vulnId} triggered a ${tuple.framework}/${tuple.controlId} failure.`,
      severity,
      status: 'open',
      source: 'auto',
      createdAt: now.toISOString(),
      createdBy: 'system:auto-mapper',
      dueAt,
      evidenceRefs: [],
      metadata: {
        ruleId: tuple.ruleId,
        slaDays,
        slaPolicy: 'calendar-days',
      },
    };

    const saved = await this.repo.create(poam);
    await this.emitPoamCreated(saved);
    return { poam: saved, deduplicated: false };
  }

  // -------------------------------------------------------------------------
  // Manual creation
  // -------------------------------------------------------------------------

  async createManual(
    tenantId: string,
    input: CreatePoamInput,
    userId: string,
  ): Promise<PoamItem> {
    const severity = input.severity;
    const slaDays = input.slaDays ?? POAM_SLA_DAYS[severity];
    const now = this.now();
    const dueAt = new Date(now.getTime() + slaDays * DAY_MS).toISOString();
    const poam: PoamItem = {
      poamId: crypto.randomUUID(),
      tenantId,
      controlId: input.controlId,
      framework: input.framework,
      vulnId: input.vulnId,
      title: input.title,
      description: input.description,
      severity,
      status: 'open',
      source: 'manual',
      createdAt: now.toISOString(),
      createdBy: userId,
      dueAt,
      evidenceRefs: [],
      metadata: input.metadata ?? {},
    };
    const saved = await this.repo.create(poam);
    await this.emitPoamCreated(saved);
    return saved;
  }

  // -------------------------------------------------------------------------
  // Read
  // -------------------------------------------------------------------------

  async get(tenantId: string, poamId: string): Promise<PoamItem | null> {
    return this.repo.getById(tenantId, poamId);
  }

  async list(tenantId: string, filter: ListPoamFilter) {
    return this.repo.list({ ...filter, tenantId });
  }

  // -------------------------------------------------------------------------
  // Status transitions
  // -------------------------------------------------------------------------

  async startProgress(tenantId: string, poamId: string, userId: string): Promise<PoamItem> {
    return this.transition(tenantId, poamId, 'in_progress', userId, {});
  }

  async markAwaitingEvidence(tenantId: string, poamId: string, userId: string): Promise<PoamItem> {
    return this.transition(tenantId, poamId, 'awaiting_evidence', userId, {});
  }

  async close(tenantId: string, poamId: string, userId: string, resolutionNotes: string, evidenceRefs: string[]): Promise<PoamItem> {
    if (evidenceRefs.length === 0) {
      throw new Error('POA&M closure requires at least one evidence record reference');
    }
    return this.transition(tenantId, poamId, 'closed', userId, {
      closedAt: this.now().toISOString(),
      closedBy: userId,
      resolutionNotes,
      evidenceRefs,
    });
  }

  async acceptRisk(
    tenantId: string,
    poamId: string,
    userId: string,
    justification: string,
    expiresAt: string,
    compensatingControlId?: string,
  ): Promise<PoamItem> {
    return this.transition(tenantId, poamId, 'risk_accepted', userId, {
      riskAcceptance: {
        acceptedBy: userId,
        acceptedAt: this.now().toISOString(),
        justification,
        expiresAt,
        compensatingControlId,
      },
    });
  }

  private async transition(
    tenantId: string,
    poamId: string,
    next: PoamStatus,
    userId: string,
    extra: Partial<PoamItem>,
  ): Promise<PoamItem> {
    const current = await this.repo.getById(tenantId, poamId);
    if (!current) throw new Error(`POA&M ${poamId} not found`);
    if (!isValidTransition(current.status, next)) {
      throw new Error(`Invalid POA&M transition: ${current.status} -> ${next}`);
    }
    const updated = await this.repo.update(tenantId, poamId, { ...extra, status: next });
    if (next === 'closed') {
      await this.emitPoamClosed(updated, userId);
    }
    return updated;
  }

  // -------------------------------------------------------------------------
  // Overdue scanning
  // -------------------------------------------------------------------------

  /**
   * Scan all open POA&M items across all tenants and mark any past-due
   * items as 'overdue'. Emits `compliance.poam.overdue` for each.
   *
   * Called by the scheduler (hourly by default).
   */
  async scanForOverdue(): Promise<PoamItem[]> {
    const grouped = await this.repo.findAllOpenGroupedByTenant();
    const now = this.now();
    const marked: PoamItem[] = [];
    for (const [tenantId, items] of grouped) {
      for (const item of items) {
        if (Date.parse(item.dueAt) > now.getTime()) continue;
        if (item.status === 'overdue') continue;
        const updated = await this.repo.update(tenantId, item.poamId, { status: 'overdue' });
        await this.emitPoamOverdue(updated);
        marked.push(updated);
      }
    }
    return marked;
  }

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  private async emitPoamCreated(poam: PoamItem): Promise<void> {
    const envelope: Omit<EventEnvelope<unknown>, 'eventId' | 'occurredAt'> = {
      type: EventTypes.COMPLIANCE_POAM_CREATED,
      version: 1,
      source: 'compliance-service',
      tenantId: poam.tenantId,
      data: {
        poamId: poam.poamId,
        controlId: poam.controlId,
        framework: poam.framework,
        vulnId: poam.vulnId,
        severity: poam.severity,
        dueAt: poam.dueAt,
        source: poam.source,
        tenantId: poam.tenantId,
      },
      severity: severityFromPoam(poam.severity),
    };
    await this.bus.publish(envelope);
  }

  private async emitPoamClosed(poam: PoamItem, userId: string): Promise<void> {
    const envelope: Omit<EventEnvelope<unknown>, 'eventId' | 'occurredAt'> = {
      type: EventTypes.COMPLIANCE_POAM_CLOSED,
      version: 1,
      source: 'compliance-service',
      tenantId: poam.tenantId,
      data: {
        poamId: poam.poamId,
        controlId: poam.controlId,
        framework: poam.framework,
        closedBy: userId,
        resolutionNotes: poam.resolutionNotes,
        evidenceRefs: poam.evidenceRefs,
        tenantId: poam.tenantId,
      },
      severity: 'notice',
    };
    await this.bus.publish(envelope);
  }

  private async emitPoamOverdue(poam: PoamItem): Promise<void> {
    const envelope: Omit<EventEnvelope<unknown>, 'eventId' | 'occurredAt'> = {
      type: EventTypes.COMPLIANCE_POAM_OVERDUE,
      version: 1,
      source: 'compliance-service',
      tenantId: poam.tenantId,
      data: {
        poamId: poam.poamId,
        controlId: poam.controlId,
        framework: poam.framework,
        severity: poam.severity,
        dueAt: poam.dueAt,
        tenantId: poam.tenantId,
      },
      severity: severityFromPoam(poam.severity),
    };
    await this.bus.publish(envelope);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityFromPoam(severity: PoamSeverity): Severity {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high': return 'alert';
    case 'medium': return 'warning';
    case 'low': return 'info';
  }
}

function mapSeverity(s: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'): PoamSeverity {
  if (s === 'info' || s === 'unknown') return 'low';
  return s;
}

const VALID_TRANSITIONS: Record<PoamStatus, ReadonlySet<PoamStatus>> = {
  open: new Set<PoamStatus>(['in_progress', 'awaiting_evidence', 'closed', 'risk_accepted', 'overdue']),
  in_progress: new Set<PoamStatus>(['open', 'awaiting_evidence', 'closed', 'risk_accepted', 'overdue']),
  awaiting_evidence: new Set<PoamStatus>(['open', 'in_progress', 'closed', 'risk_accepted', 'overdue']),
  overdue: new Set<PoamStatus>(['in_progress', 'awaiting_evidence', 'closed', 'risk_accepted', 'open']),
  closed: new Set<PoamStatus>(['open']),
  risk_accepted: new Set<PoamStatus>(['open', 'closed']),
};

export function isValidTransition(from: PoamStatus, to: PoamStatus): boolean {
  return VALID_TRANSITIONS[from]?.has(to) ?? false;
}
