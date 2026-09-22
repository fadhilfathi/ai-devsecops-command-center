import { describe, test, expect, vi } from 'vitest';
import { RedisStreamsEventBus, type RedisLike } from './redis.js';
import { InMemoryEventBus, type EventBus, type EventEnvelope } from './index.js';
import type { Logger } from '../logger/index.js';

const silentLogger = {
  error: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
} as unknown as Logger;

/**
 * Minimal in-memory stand-in for the ioredis client, backed by one
 * append-only array per stream (shared across `duplicate()`d connections
 * so they behave like multiple clients against the same server) plus
 * per-group cursors/pending sets.
 */
class FakeRedisServer {
  streams = new Map<string, Array<{ id: string; fields: string[] }>>();
  groups = new Map<string, Map<string, { cursor: number; pending: Set<string> }>>();
  seq = 0;

  nextId(): string {
    this.seq += 1;
    return `${Date.now()}-${this.seq}`;
  }
}

class FakeRedis implements RedisLike {
  constructor(private readonly server: FakeRedisServer) {}

  async xadd(...args: unknown[]): Promise<unknown> {
    const [key, , , , , field, value] = args as string[];
    const id = this.server.nextId();
    const list = this.server.streams.get(key) ?? [];
    list.push({ id, fields: [field, value] });
    this.server.streams.set(key, list);
    return id;
  }

  async xgroup(...args: unknown[]): Promise<unknown> {
    const [, key, group] = args as string[];
    let groupMap = this.server.groups.get(key);
    if (!groupMap) {
      groupMap = new Map();
      this.server.groups.set(key, groupMap);
    }
    if (groupMap.has(group)) {
      throw new Error('BUSYGROUP Consumer Group name already exists');
    }
    groupMap.set(group, {
      cursor: (this.server.streams.get(key) ?? []).length,
      pending: new Set(),
    });
    return 'OK';
  }

  async xreadgroup(...args: unknown[]): Promise<unknown> {
    // GROUP group consumer COUNT n BLOCK ms STREAMS key >
    const [, group, , , count, , , , key] = args as [
      string,
      string,
      string,
      string,
      number,
      string,
      number,
      string,
      string,
    ];
    const groupState = this.server.groups.get(key)?.get(group);
    if (!groupState) return null;
    const all = this.server.streams.get(key) ?? [];
    const pending = all.slice(groupState.cursor, groupState.cursor + count);
    if (pending.length === 0) {
      // Simulate BLOCK: a short real delay instead of the requested
      // blockMs so tests stay fast.
      await new Promise((r) => setTimeout(r, 5));
      return null;
    }
    groupState.cursor += pending.length;
    for (const m of pending) groupState.pending.add(m.id);
    return [[key, pending.map((m) => [m.id, m.fields])]];
  }

  async xack(...args: unknown[]): Promise<unknown> {
    const [key, group, id] = args as string[];
    this.server.groups.get(key)?.get(group)?.pending.delete(id);
    return 1;
  }

  async ping(): Promise<unknown> {
    return 'PONG';
  }

  async quit(): Promise<unknown> {
    return 'OK';
  }

  duplicate(): RedisLike {
    return new FakeRedis(this.server);
  }
}

function makeBus(overrides: Partial<{ serviceName: string; blockMs: number }> = {}): {
  bus: RedisStreamsEventBus;
  server: FakeRedisServer;
} {
  const server = new FakeRedisServer();
  const bus = new RedisStreamsEventBus({
    url: 'redis://fake',
    serviceName: overrides.serviceName ?? 'test-service',
    logger: silentLogger,
    blockMs: overrides.blockMs ?? 20,
    redisFactory: () => new FakeRedis(server),
  });
  return { bus, server };
}

async function waitFor(assertion: () => void, timeoutMs = 1000): Promise<void> {
  const start = Date.now();
  for (;;) {
    try {
      assertion();
      return;
    } catch (err) {
      if (Date.now() - start > timeoutMs) throw err;
      await new Promise((r) => setTimeout(r, 10));
    }
  }
}

test('publish then subscribe delivers the event, sealed with eventId/occurredAt', async () => {
  const { bus } = makeBus();
  const received: EventEnvelope[] = [];
  await bus.subscribe('test.event', (e) => {
    received.push(e);
  });
  await bus.publish({
    type: 'test.event',
    version: 1,
    source: 'test',
    tenantId: 't-1',
    data: { hello: 'world' },
  });

  await waitFor(() => expect(received).toHaveLength(1));
  expect(received[0]?.eventId).toBeTruthy();
  expect(received[0]?.occurredAt).toBeTruthy();
  expect(received[0]?.data).toEqual({ hello: 'world' });

  await bus.close();
});

test('group is created once with MKSTREAM; BUSYGROUP on a second subscribe is ignored', async () => {
  const { bus, server } = makeBus();
  await bus.subscribe('test.event', () => {});
  await bus.subscribe('test.event', () => {}); // second handler, same group -> BUSYGROUP internally, must not throw

  expect(server.groups.get('aicc:events:test.event')?.size).toBe(1);
  await bus.close();
});

test('handler throw leaves the message pending (no XACK)', async () => {
  const { bus, server } = makeBus();
  await bus.subscribe('test.event', () => {
    throw new Error('boom');
  });
  await bus.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} });

  await waitFor(() => {
    const groupState = server.groups.get('aicc:events:test.event')?.get('test-service');
    expect(groupState?.pending.size).toBe(1);
  });

  await bus.close();
});

test('close() stops the read loop and is idempotent', async () => {
  const { bus } = makeBus();
  await bus.subscribe('test.event', () => {});
  await bus.close();
  await expect(bus.close()).resolves.toBeUndefined();
  await expect(
    bus.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} }),
  ).rejects.toThrow(/closed/i);
});

test('two subscribers in different groups (services) each get their own copy', async () => {
  const server = new FakeRedisServer();
  const busA = new RedisStreamsEventBus({
    url: 'redis://fake',
    serviceName: 'service-a',
    logger: silentLogger,
    blockMs: 20,
    redisFactory: () => new FakeRedis(server),
  });
  const busB = new RedisStreamsEventBus({
    url: 'redis://fake',
    serviceName: 'service-b',
    logger: silentLogger,
    blockMs: 20,
    redisFactory: () => new FakeRedis(server),
  });

  let a = 0;
  let b = 0;
  await busA.subscribe('test.event', () => {
    a += 1;
  });
  await busB.subscribe('test.event', () => {
    b += 1;
  });
  await busA.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} });

  await waitFor(() => {
    expect(a).toBe(1);
    expect(b).toBe(1);
  });

  await busA.close();
  await busB.close();
});

test('same group (two consumers of the same service) only delivers once', async () => {
  const { bus } = makeBus();
  let count = 0;
  await bus.subscribe('test.event', () => {
    count += 1;
  });
  await bus.subscribe('test.event', () => {
    count += 1;
  });
  await bus.publish({ type: 'test.event', version: 1, source: 'test', tenantId: 't-1', data: {} });

  await waitFor(() => expect(count).toBe(1));
  // Give the second consumer's poll loop a chance to run too — it
  // shouldn't find anything new since the first consumer already
  // advanced the shared group cursor.
  await new Promise((r) => setTimeout(r, 60));
  expect(count).toBe(1);

  await bus.close();
});

describe.each([
  ['InMemoryEventBus', () => new InMemoryEventBus() as EventBus],
  [
    'RedisStreamsEventBus',
    () =>
      new RedisStreamsEventBus({
        url: 'redis://fake',
        serviceName: 'parity-service',
        logger: silentLogger,
        blockMs: 20,
        redisFactory: () => new FakeRedis(new FakeRedisServer()),
      }) as EventBus,
  ],
])('%s parity', (_name, makeParityBus) => {
  test('publish delivers to a subscribed handler', async () => {
    const bus = makeParityBus();
    const received: unknown[] = [];
    await bus.subscribe('parity.event', (e: EventEnvelope) => {
      received.push(e.data);
    });
    await bus.publish({
      type: 'parity.event',
      version: 1,
      source: 'test',
      tenantId: 't-1',
      data: { hello: 'world' },
    });

    await waitFor(() => expect(received).toEqual([{ hello: 'world' }]));
    await bus.close();
  });

  test('publish after close rejects', async () => {
    const bus = makeParityBus();
    await bus.close();
    await expect(
      bus.publish({ type: 'parity.event', version: 1, source: 'test', tenantId: 't-1', data: {} }),
    ).rejects.toThrow(/closed/i);
  });
});
