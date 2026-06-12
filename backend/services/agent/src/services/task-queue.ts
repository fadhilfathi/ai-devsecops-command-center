/**
 * In-process task queue for the agent orchestrator.
 *
 * Sprint 1 ships a simple FIFO. Sprint 2 will use a durable queue
 * (BullMQ / Postgres-backed) per the SREEngineer's plan.
 */
import type { UUID, ISO8601 } from '@aicc/shared';

export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface AgentTask {
  id: UUID;
  kind: string;
  tenantId: UUID;
  status: TaskStatus;
  input: Record<string, unknown>;
  result?: unknown;
  error?: string;
  createdAt: ISO8601;
  startedAt?: ISO8601;
  finishedAt?: ISO8601;
}

export interface TaskQueue {
  enqueue(input: { kind: string; tenantId: UUID; payload: Record<string, unknown> }): Promise<AgentTask>;
  dequeue(): Promise<AgentTask | undefined>;
  complete(id: UUID, result: unknown): Promise<AgentTask | undefined>;
  fail(id: UUID, error: string): Promise<AgentTask | undefined>;
  list(tenantId?: UUID): Promise<AgentTask[]>;
  findById(id: UUID): Promise<AgentTask | undefined>;
  size(): number;
}

function newId(): UUID {
  return globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

export function buildTaskQueue(): TaskQueue {
  const tasks = new Map<UUID, AgentTask>();
  const order: UUID[] = [];

  return {
    async enqueue({ kind, tenantId, payload }) {
      const now = new Date().toISOString();
      const task: AgentTask = {
        id: newId(),
        kind,
        tenantId,
        status: 'pending',
        input: payload,
        createdAt: now,
      };
      tasks.set(task.id, task);
      order.push(task.id);
      return task;
    },
    async dequeue() {
      while (order.length > 0) {
        const id = order.shift()!;
        const t = tasks.get(id);
        if (!t) continue;
        if (t.status !== 'pending') continue;
        t.status = 'running';
        t.startedAt = new Date().toISOString();
        return t;
      }
      return undefined;
    },
    async complete(id, result) {
      const t = tasks.get(id);
      if (!t) return undefined;
      t.status = 'completed';
      t.result = result;
      t.finishedAt = new Date().toISOString();
      return t;
    },
    async fail(id, error) {
      const t = tasks.get(id);
      if (!t) return undefined;
      t.status = 'failed';
      t.error = error;
      t.finishedAt = new Date().toISOString();
      return t;
    },
    async list(tenantId) {
      const arr = Array.from(tasks.values());
      return tenantId ? arr.filter((t) => t.tenantId === tenantId) : arr;
    },
    async findById(id) {
      return tasks.get(id);
    },
    size() {
      return order.length;
    },
  };
}
