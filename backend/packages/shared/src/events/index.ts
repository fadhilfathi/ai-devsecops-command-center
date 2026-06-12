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

import type { UUID, ISO8601, Severity } from '../types/index.js';

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
  occurredAt: ISO8601;
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
}

function newId(): UUID {
  // Lightweight RFC4122-ish v4. Replace with `crypto.randomUUID()` when stable.
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
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
    const envelope: EventEnvelope<T> = {
      eventId: newId(),
      occurredAt: new Date().toISOString(),
      ...event,
    };
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
  INTEGRATION_SYNC_COMPLETED: 'integration.sync.completed',
} as const;

export type EventType = (typeof EventTypes)[keyof typeof EventTypes];
