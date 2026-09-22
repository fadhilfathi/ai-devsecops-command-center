/**
 * Event bus contracts and lightweight in-memory publisher.
 *
 * The Sprint 1 skeleton ships an in-process implementation. The
 * PlatformArchitect agent will finalize the Redis Streams / NATS
 * implementation in the "Event Bus & Agent Communication Design" task.
 *
 * All services publish events through this interface so that switching
 * the transport is a one-line change.
 */

import type { UUID, ISOTimestamp, Severity } from '../types/index.js';
import type { Logger } from '../logger/index.js';
import { RedisStreamsEventBus } from './redis.js';

export type { UUID, ISOTimestamp, Severity };
export { RedisStreamsEventBus } from './redis.js';
export type { RedisStreamsEventBusOptions } from './redis.js';

export interface EventEnvelope<T = unknown> {
  /** Unique event id, useful for idempotency. */
  eventId: UUID;
  /** Event type in dotted notation, e.g. "scan.completed". */
  type: string;
  /** Schema version of the payload, allows evolution. */
  version: number;
  /** Origin service that produced the event. */
  source: string;
  /** When the event was produced. */
  occurredAt: ISOTimestamp;
  /** Tenant scope for multi-tenant isolation. */
  tenantId: UUID;
  /** Optional correlation id for tracing across services. */
  correlationId?: string;
  /** The event payload. */
  data: T;
  /** Optional severity hint for routing and alerting. */
  severity?: Severity;
}

export type EventHandler<T = unknown> = (event: EventEnvelope<T>) => Promise<void> | void;

export interface EventBus {
  publish<T>(event: Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>): Promise<void>;
  subscribe<T>(type: string, handler: EventHandler<T>): Promise<void>;
  close(): Promise<void>;
  /** Optional connectivity probe for /readyz. Drivers without a real
   * connection (e.g. in-memory) omit it. */
  ping?(): Promise<void>;
}

function newId(): UUID {
  // Lightweight RFC4122-ish v4. Replace with `crypto.randomUUID()` when stable.
  return (
    globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    })
  );
}

/**
 * Fills in `eventId`/`occurredAt`. Shared by every `EventBus` implementation
 * so they can't drift on envelope shape.
 */
export function sealEnvelope<T>(
  event: Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>,
): EventEnvelope<T> {
  return {
    eventId: newId(),
    occurredAt: new Date().toISOString(),
    ...event,
  };
}

/**
 * In-memory event bus. Useful for tests, local dev, and as the
 * default when no broker is configured.
 */
export class InMemoryEventBus implements EventBus {
  private readonly handlers = new Map<string, Set<EventHandler>>();
  private closed = false;

  async publish<T>(event: Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>): Promise<void> {
    if (this.closed) {
      throw new Error('EventBus is closed');
    }
    const envelope = sealEnvelope(event);
    const set = this.handlers.get(envelope.type);
    if (!set || set.size === 0) return;
    // Fan out; errors are isolated to each handler.
    await Promise.all(
      Array.from(set).map(async (h) => {
        try {
          await h(envelope);
        } catch (err) {
          // The SREEngineer will own the global error reporter.
          // eslint-disable-next-line no-console
          console.error('[EventBus] handler threw', { type: envelope.type, err });
        }
      }),
    );
  }

  async subscribe<T>(type: string, handler: EventHandler<T>): Promise<void> {
    let set = this.handlers.get(type);
    if (!set) {
      set = new Set();
      this.handlers.set(type, set);
    }
    set.add(handler as EventHandler);
  }

  async close(): Promise<void> {
    this.closed = true;
    this.handlers.clear();
  }
}

/** Canonical event types used across services. Add new ones here. */
export const EventTypes = {
  AUTH_USER_LOGGED_IN: 'auth.user.logged_in',
  AUTH_USER_LOGGED_OUT: 'auth.user.logged_out',
  AGENT_TASK_REQUESTED: 'agent.task.requested',
  AGENT_TASK_COMPLETED: 'agent.task.completed',
  SCAN_STARTED: 'scan.started',
  SCAN_COMPLETED: 'scan.completed',
  SCAN_FAILED: 'scan.failed',
  VULNERABILITY_DETECTED: 'vulnerability.detected',
  INCIDENT_CREATED: 'incident.created',
  INCIDENT_RESOLVED: 'incident.resolved',
  COMPLIANCE_CONTROL_UPDATED: 'compliance.control.updated',
  COMPLIANCE_CONTROL_VIOLATED: 'compliance.control.violated',
  COMPLIANCE_EVIDENCE_ATTACHED: 'compliance.evidence.attached',
  COMPLIANCE_POAM_CREATED: 'compliance.poam.created',
  COMPLIANCE_POAM_CLOSED: 'compliance.poam.closed',
  COMPLIANCE_POAM_OVERDUE: 'compliance.poam.overdue',
  INTEGRATION_SYNC_COMPLETED: 'integration.sync.completed',
  RUNTIME_RISK_DETECTED: 'runtime.risk.detected',
  CLUSTER_HEALTH_ISSUE_DETECTED: 'cluster.health.issue.detected',
} as const;

export type EventType = (typeof EventTypes)[keyof typeof EventTypes];

export interface EventBusConfig {
  driver: 'memory' | 'redis';
  redisUrl?: string;
}

export interface CreateEventBusOptions extends EventBusConfig {
  serviceName: string;
  logger: Logger;
}

/**
 * Builds the configured `EventBus` implementation. `memory` (default) is
 * the Sprint 1 in-process bus; `redis` uses Redis Streams (S6-3). Every
 * service does `deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName, logger })`
 * so switching drivers is a one-line env var change, never a code change.
 */
export function createEventBus(opts: CreateEventBusOptions): EventBus {
  if (opts.driver === 'redis') {
    if (!opts.redisUrl) {
      throw new Error('EVENT_BUS_DRIVER=redis requires REDIS_URL to be set');
    }
    return new RedisStreamsEventBus({
      url: opts.redisUrl,
      serviceName: opts.serviceName,
      logger: opts.logger,
    });
  }
  return new InMemoryEventBus();
}
