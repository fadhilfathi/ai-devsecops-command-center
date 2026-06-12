// Evidence auto-attacher
//
// When a scan completes, the compliance service:
//
//   1. Receives a `scan.completed` event from the bus (or a direct
//      service-to-service call).
//   2. Runs the mapping engine over the findings -> (controlId, vulnId)
//      tuples.
//   3. For each affected control, persists the SBOM and the scan
//      report to object storage, creates an Evidence record per
//      control, and emits `compliance.evidence.attached`.
//   4. Triggers POA&M auto-creation for any non-compliant control
//      (those with at least one failing tuple).
//
// Object storage is abstracted behind a `BlobStore` interface so the
// implementation can be swapped (S3, GCS, Azure Blob, in-memory for
// dev) without changing this file.

import { createHash, randomUUID } from 'node:crypto';
import type { EventEnvelope, EventBus, UUID } from '@aicc/shared';
import { EventTypes, type Severity } from '@aicc/shared/events';
import type { EvidenceRepository, EvidenceRecord } from '../repositories/evidence.repository.js';
import type { MappingEngine } from '../control-mapper/index.js';
import type { PoamService } from '../poam/poam.service.js';
import { withAudit } from '../observability/audit.js';

/** Minimal blob store interface. The Sprint 2 impl is in-memory; Sprint 3
 *  is the cloud provider. */
export interface BlobStore {
  put(key: string, body: Buffer | Uint8Array | string, contentType: string): Promise<{ key: string; hash: string; size: number }>;
  get(key: string): Promise<Buffer | null>;
}

export interface AttachScanInput {
  tenantId: UUID;
  assetId: string;
  scanId: string;
  tool: string; // 'trivy' | 'grype' | 'syft' | etc.
  /** SBOM document (CycloneDX or SPDX JSON serialized). */
  sbom: object;
  /** Scanner report (vulnerabilities + metadata). */
  scanReport: object;
  /** Pre-mapped findings (optional; if absent, mapping engine is run). */
  preMappedControlIds?: string[];
}

export interface AttachScanResult {
  evidenceIds: string[];
  attachedControls: string[];
  poamCreated: number;
  poamDeduplicated: number;
}

export interface EvidenceAttacherDeps {
  store: BlobStore;
  evidenceRepo: EvidenceRepository;
  mappingEngine: MappingEngine;
  poamService: PoamService;
  bus: EventBus;
  /** Collector identity stamped on evidence records. */
  collectedBy?: UUID;
}

export class EvidenceAttacher {
  private readonly store: BlobStore;
  private readonly evidenceRepo: EvidenceRepository;
  private readonly mappingEngine: MappingEngine;
  private readonly poamService: PoamService;
  private readonly bus: EventBus;
  private readonly collectedBy: UUID;

  constructor(deps: EvidenceAttacherDeps) {
    this.store = deps.store;
    this.evidenceRepo = deps.evidenceRepo;
    this.mappingEngine = deps.mappingEngine;
    this.poamService = deps.poamService;
    this.bus = deps.bus;
    this.collectedBy = (deps.collectedBy ?? '00000000-0000-4000-8000-000000000001') as UUID;
  }

  /**
   * Attach SBOM and scan report to all controls implicated by the
   * scan. Auto-create POA&M items for non-compliant controls.
   */
  async attach(input: AttachScanInput): Promise<AttachScanResult> {
    const now = new Date().toISOString();
    const controlIds = new Set<string>(input.preMappedControlIds ?? []);
    let poamCreated = 0;
    let poamDeduplicated = 0;

    // 1. Run mapping engine over the scan report's findings.
    const findings = extractFindings(input.scanReport);
    if (findings.length > 0) {
      const batch = this.mappingEngine.evaluateFindings(
        findings.map((f) => ({ ...f, tenantId: input.tenantId, assetId: input.assetId })) as any,
      );
      for (const tuple of batch.tuples) controlIds.add(tuple.controlId);

      // 2. Auto-create POA&M items for each tuple (deduped).
      for (const tuple of batch.tuples) {
        const r = await this.poamService.createFromTuple(input.tenantId, tuple);
        if (r.deduplicated) poamDeduplicated += 1;
        else poamCreated += 1;
      }

      // 3. Emit compliance.control.violated for non-compliant controls.
      for (const [controlId, summary] of batch.controlSummary) {
        await this.emitControlViolated({
          tenantId: input.tenantId as string,
          controlId,
          framework: summary.framework as any,
          status: 'fail',
          violatingVulnIds: summary.vulnIds,
          firstObservedAt: now,
          highestSeverity: summary.highestSeverity,
          ruleIds: batch.tuples.filter((t) => t.controlId === controlId).map((t) => t.ruleId),
        });
      }
    }

    // 4. Persist SBOM and scan report; create one evidence record per
    //    (controlId, evidenceType) pair so each control has its own
    //    evidence pointer.
    const evidenceIds: string[] = [];
    const sbomJson = JSON.stringify(input.sbom);
    const reportJson = JSON.stringify(input.scanReport);

    const sbomStored = await this.store.put(
      `tenants/${input.tenantId}/assets/${input.assetId}/scans/${input.scanId}/sbom.json`,
      sbomJson,
      'application/json',
    );
    const reportStored = await this.store.put(
      `tenants/${input.tenantId}/assets/${input.assetId}/scans/${input.scanId}/report.json`,
      reportJson,
      'application/json',
    );

    for (const controlId of controlIds) {
      const sbomEv = await this.evidenceRepo.create({
        tenantId: input.tenantId,
        controlId: controlId as UUID,
        kind: 'config', // SBOM is a configuration artefact
        description: `SBOM (${input.tool}) for asset ${input.assetId} (scan ${input.scanId}); sha256=${sbomStored.hash}`,
        ref: sbomStored.key,
        collectedBy: this.collectedBy,
      });
      evidenceIds.push(sbomEv.id);
      await this.emitEvidenceAttached(sbomEv, input);

      const reportEv = await this.evidenceRepo.create({
        tenantId: input.tenantId,
        controlId: controlId as UUID,
        kind: 'log', // scan report is logged output
        description: `Scan report (${input.tool}) for asset ${input.assetId} (scan ${input.scanId}); sha256=${reportStored.hash}`,
        ref: reportStored.key,
        collectedBy: this.collectedBy,
      });
      evidenceIds.push(reportEv.id);
      await this.emitEvidenceAttached(reportEv, input);
    }

    return {
      evidenceIds,
      attachedControls: Array.from(controlIds),
      poamCreated,
      poamDeduplicated,
    };
  }

  // -------------------------------------------------------------------------
  // Event emission
  // -------------------------------------------------------------------------

  private async emitControlViolated(data: import('./compliance.events.js').ComplianceControlViolatedData): Promise<void> {
    const envelope: Omit<EventEnvelope<unknown>, 'eventId' | 'occurredAt'> = {
      type: EventTypes.COMPLIANCE_CONTROL_VIOLATED,
      version: 1,
      source: 'compliance-service',
      tenantId: data.tenantId,
      data,
      severity: severityFromVuln(data.highestSeverity),
    };
    await withAudit(
      { tenantId: data.tenantId, auditKind: 'control.violated', subjectId: data.controlId, detail: { framework: data.framework, highestSeverity: data.highestSeverity, violatingVulnCount: data.violatingVulnIds.length, scanId: data.scanId } },
      () => this.bus.publish(envelope),
    );
  }

  private async emitEvidenceAttached(record: EvidenceRecord, input: AttachScanInput): Promise<void> {
    const envelope: Omit<EventEnvelope<unknown>, 'eventId' | 'occurredAt'> = {
      type: EventTypes.COMPLIANCE_EVIDENCE_ATTACHED,
      version: 1,
      source: 'compliance-service',
      tenantId: record.tenantId,
      data: {
        tenantId: record.tenantId,
        evidenceId: record.id,
        controlIds: [record.controlId],
        assetId: input.assetId,
        evidenceType: record.kind as any,
        objectStorePath: record.ref,
        hash: extractHashFromDescription(record.description) ?? '',
        scanId: input.scanId,
        tool: input.tool,
        collectedBy: record.collectedBy,
        collectedAt: record.collectedAt,
      },
      severity: 'info',
    };
    await withAudit(
      { tenantId: record.tenantId, auditKind: 'evidence.attached', subjectId: record.id, detail: { controlId: record.controlId, kind: record.kind, assetId: input.assetId, scanId: input.scanId, tool: input.tool } },
      () => this.bus.publish(envelope),
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityFromVuln(s: string): Severity {
  switch (s) {
    case 'critical': return 'critical';
    case 'high': return 'alert';
    case 'medium': return 'warning';
    case 'low': return 'info';
    default: return 'info';
  }
}

function extractHashFromDescription(description: string): string | null {
  const m = description.match(/sha256=([a-f0-9:]+)/i);
  return m ? m[1] : null;
}

/**
 * Extract vulnerability findings from a scanner report. The Sprint 2
 * format is the union of Trivy and Grype normalized shapes. Unknown
 * fields are preserved in metadata.
 */
function extractFindings(report: any): Array<{
  id: string;
  cveId?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  status?: 'open' | 'confirmed' | 'false_positive' | 'resolved' | 'suppressed';
  kev?: boolean;
  introducedAt?: string;
  assetId: string;
  componentId?: string;
  metadata?: Record<string, unknown>;
}> {
  const findings = report?.findings ?? report?.vulnerabilities ?? report?.results ?? [];
  if (!Array.isArray(findings)) return [];
  return findings.map((f: any, idx: number) => ({
    id: f.id ?? f.vulnId ?? f.issue_id ?? `finding-${idx}`,
    cveId: f.cveId ?? f.cve_id ?? f.cve,
    severity: normalizeSev(f.severity ?? f.severity_v4 ?? f.cvss_v3_severity),
    status: f.status,
    kev: Boolean(f.kev ?? f.is_known_exploited),
    introducedAt: f.introducedAt ?? f.introduced_at ?? f.published_at,
    assetId: f.assetId ?? f.asset_id ?? 'unknown',
    componentId: f.packageName ?? f.package_name ?? f.component,
    metadata: f.metadata ?? { raw: f },
  }));
}

function normalizeSev(s: any): 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown' {
  if (typeof s !== 'string') return 'unknown';
  const v = s.toLowerCase();
  if (v.includes('crit')) return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium' || v === 'moderate' || v === 'med') return 'medium';
  if (v === 'low') return 'low';
  if (v === 'info' || v === 'negligible' || v === 'informational') return 'info';
  return 'unknown';
}
