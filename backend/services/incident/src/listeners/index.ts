/**
 * In-process event listeners.
 *
 * Sprint 1: react to events from other services running in the same
 * process (or via the in-memory bus). When we move to a broker in
 * Sprint 2, the bus swap is transparent — these handlers will keep
 * working as long as a matching topic is configured.
 */
import {
  EventTypes,
  type EventBus,
  type EventEnvelope,
  type Logger,
  type UUID,
} from '@aicc/shared';
import type { IncidentRepository } from '../repositories/incident.repository.js';

interface Deps {
  bus: EventBus;
  incidents: IncidentRepository;
  logger: Logger;
}

export async function buildEventListeners(deps: Deps): Promise<void> {
  // Auto-open an incident on critical vulnerability detection.
  await deps.bus.subscribe<{ findingId: string; cveId?: string; severity: string }>(
    EventTypes.VULNERABILITY_DETECTED,
    async (event: EventEnvelope<{ findingId: string; cveId?: string; severity: string }>) => {
      if (event.data.severity !== 'critical') return;
      const incident = await deps.incidents.create({
        tenantId: event.tenantId as UUID,
        title: `Critical vulnerability: ${event.data.cveId ?? event.data.findingId}`,
        description: `Auto-opened from security-service event ${event.eventId}`,
        severity: 'critical',
        relatedFindingIds: [event.data.findingId],
      });
      deps.logger.warn({ incidentId: incident.id, findingId: event.data.findingId }, 'auto-opened incident');
    },
  );

  // Re-evaluate on agent task completion (triage result).
  await deps.bus.subscribe<{ taskId: string; result?: { decision?: string } }>(
    EventTypes.AGENT_TASK_COMPLETED,
    async (event) => {
      if (event.data.result?.decision === 'open_incident') {
        deps.logger.info({ taskId: event.data.taskId }, 'triage requested incident creation');
      }
    },
  );
}
