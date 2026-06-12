// Scan event listener
//
// Subscribes to `security.scan.completed` on the bus and forwards the
// payload to the EvidenceAttacher. The listener is tenant-isolated:
// it processes events for any tenant the compliance service is
// authorized to act on.
//
// Idempotency: the attacher is keyed by scanId (deduplicated at the
// event bus consumer level for at-least-once delivery). Re-processing
// the same scan is a no-op for POA&M (dedup at POA&M service) and
// creates additional evidence records with the same content hash but
// new evidenceIds (acceptable — evidence is append-only).

import type { EventEnvelope, EventHandler } from '@aicc/shared/events';
import { EventTypes } from '@aicc/shared/events';
import type { EvidenceAttacher, AttachScanInput } from './evidence-attacher.js';

export interface ScanCompletedEvent {
  tenantId: string;
  assetId: string;
  scanId: string;
  tool: string;
  sbom: object;
  scanReport: object;
}

export function buildScanListener(attacher: EvidenceAttacher): {
  topic: string;
  handler: EventHandler;
} {
  const handler: EventHandler = async (envelope: EventEnvelope<unknown>) => {
    if (envelope.type !== EventTypes.SCAN_COMPLETED) {
      // Ignore unrelated events.
      return;
    }
    const data = envelope.data as ScanCompletedEvent;
    if (!data?.tenantId || !data?.assetId || !data?.scanId) {
      // Malformed event — log and skip.
      return;
    }
    const input: AttachScanInput = {
      tenantId: data.tenantId,
      assetId: data.assetId,
      scanId: data.scanId,
      tool: data.tool,
      sbom: data.sbom,
      scanReport: data.scanReport,
    };
    await attacher.attach(input);
  };
  return { topic: EventTypes.SCAN_COMPLETED, handler };
}
