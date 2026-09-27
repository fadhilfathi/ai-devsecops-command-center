/**
 * Redis Streams backed `EventBus`.
 *
 * One stream per event type (`aicc:events:<type>`), one consumer group
 * per subscribing service (so every service gets its own copy of the
 * stream — fan-out via groups rather than pub/sub, which gives us
 * durability and at-least-once delivery). A crashed/failed consumer's
 * pending entries are periodically reclaimed via `XAUTOCLAIM` and,
 * after `maxDeliveries` attempts, moved to a dead-letter stream
 * (`aicc:events:dlq:<type>`). See
 * `docs/adr/0014-redis-streams-event-bus.md` for the rationale and the
 * remaining deferred work (trimming vs. pending entries, ordering).
 */
import { Redis } from 'ioredis';
import type { Logger } from '../logger/index.js';
import { sealEnvelope, type EventBus, type EventEnvelope, type EventHandler } from './index.js';

/**
 * The slice of the ioredis client this bus actually calls. Kept minimal
 * (rather than depending on the full `Redis` class type) so tests can
 * inject a `FakeRedis` without satisfying dozens of unrelated overloads.
 */
export interface RedisLike {
  xadd(...args: unknown[]): Promise<unknown>;
  xgroup(...args: unknown[]): Promise<unknown>;
  xreadgroup(...args: unknown[]): Promise<unknown>;
  xack(...args: unknown[]): Promise<unknown>;
  xautoclaim(...args: unknown[]): Promise<unknown>;
  xpending(...args: unknown[]): Promise<unknown>;
  ping(): Promise<unknown>;
  quit(): Promise<unknown>;
  duplicate(): RedisLike;
}

export interface RedisStreamsEventBusOptions {
  url: string;
  serviceName: string;
  logger: Logger;
  /** `XADD ... MAXLEN ~ <maxLen>`. Default 10000. */
  maxLen?: number;
  /** `XREADGROUP ... BLOCK <blockMs>`. Default 5000. */
  blockMs?: number;
  /** Pause after a failed read before retrying. Default 1000. */
  errorBackoffMs?: number;
  /** How often the read loop checks for stale pending entries to reclaim. Default 30000. */
  reclaimIntervalMs?: number;
  /** `XAUTOCLAIM` min-idle-time — only reclaim entries pending at least this long. Default 60000. */
  minIdleMs?: number;
  /** Deliveries (initial + reclaims) allowed before an entry is dead-lettered. Default 5. */
  maxDeliveries?: number;
  /** Injectable for tests — must return something shaped like ioredis. */
  redisFactory?: (url: string) => RedisLike;
}

function streamKey(type: string): string {
  // Sanitise so arbitrary event-type strings can't inject stream keys
  // with characters Redis keys don't like in practice.
  return `aicc:events:${type.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
}

function dlqKeyFor(key: string): string {
  return key.replace(/^aicc:events:/, 'aicc:events:dlq:');
}

function shortRandom(): string {
  return Math.random().toString(36).slice(2, 8);
}

interface Subscription {
  group: string;
  consumer: string;
  handler: EventHandler;
}

export class RedisStreamsEventBus implements EventBus {
  private readonly maxLen: number;
  private readonly blockMs: number;
  private readonly errorBackoffMs: number;
  private readonly reclaimIntervalMs: number;
  private readonly minIdleMs: number;
  private readonly maxDeliveries: number;
  private readonly serviceName: string;
  private readonly logger: Logger;
  private readonly factory: (url: string) => RedisLike;
  private readonly url: string;
  private readonly publisher: RedisLike;
  private readonly subscriberConns = new Set<RedisLike>();
  private readonly loops: Promise<void>[] = [];
  private readonly groupsCreated = new Set<string>();
  private closed = false;
  private closing = false;

  constructor(options: RedisStreamsEventBusOptions) {
    this.maxLen = options.maxLen ?? 10000;
    this.blockMs = options.blockMs ?? 5000;
    this.errorBackoffMs = options.errorBackoffMs ?? 1000;
    this.reclaimIntervalMs = options.reclaimIntervalMs ?? 30000;
    this.minIdleMs = options.minIdleMs ?? 60000;
    this.maxDeliveries = options.maxDeliveries ?? 5;
    this.serviceName = options.serviceName;
    this.logger = options.logger;
    this.url = options.url;
    this.factory = options.redisFactory ?? ((url) => new Redis(url) as unknown as RedisLike);
    this.publisher = this.factory(this.url);
  }

  async publish<T>(event: Omit<EventEnvelope<T>, 'eventId' | 'occurredAt'>): Promise<void> {
    if (this.closed) {
      throw new Error('EventBus is closed');
    }
    const envelope = sealEnvelope(event);
    await this.publisher.xadd(
      streamKey(envelope.type),
      'MAXLEN',
      '~',
      String(this.maxLen),
      '*',
      'envelope',
      JSON.stringify(envelope),
    );
  }

  async subscribe<T>(type: string, handler: EventHandler<T>): Promise<void> {
    if (this.closed) {
      throw new Error('EventBus is closed');
    }
    const key = streamKey(type);
    const group = this.serviceName;
    const consumer = `${this.serviceName}-${process.pid}-${shortRandom()}`;

    const groupKey = `${key}:${group}`;
    if (!this.groupsCreated.has(groupKey)) {
      try {
        await this.publisher.xgroup('CREATE', key, group, '$', 'MKSTREAM');
      } catch (err) {
        // BUSYGROUP = another instance of this service already created it.
        if (!(err instanceof Error) || !/BUSYGROUP/.test(err.message)) {
          throw err;
        }
      }
      this.groupsCreated.add(groupKey);
    }

    const conn = this.publisher.duplicate();
    this.subscriberConns.add(conn);

    const sub: Subscription = { group, consumer, handler: handler as EventHandler };
    this.loops.push(this.readLoop(conn, key, sub));
  }

  private async readLoop(conn: RedisLike, key: string, sub: Subscription): Promise<void> {
    let lastReclaim = Date.now();
    while (!this.closing) {
      if (Date.now() - lastReclaim >= this.reclaimIntervalMs) {
        lastReclaim = Date.now();
        await this.reclaimStale(conn, key, sub);
        if (this.closing) return;
      }

      let result: unknown;
      try {
        result = await conn.xreadgroup(
          'GROUP',
          sub.group,
          sub.consumer,
          'COUNT',
          10,
          'BLOCK',
          this.blockMs,
          'STREAMS',
          key,
          '>',
        );
      } catch (err) {
        if (this.closing) return;
        this.logger.error({ err, key }, '[RedisStreamsEventBus] xreadgroup failed');
        // Back off so a persistent failure (bad group, auth, connection
        // refused) cannot spin the loop hot against Redis.
        await sleep(this.errorBackoffMs);
        continue;
      }
      if (!result) continue;

      // ioredis shape: [[streamKey, [[id, [field, value, ...]], ...]]]
      const streams = result as Array<[string, Array<[string, string[]]>]>;
      for (const [, messages] of streams) {
        for (const [id, fields] of messages) {
          await this.processEntry(conn, key, sub, id, fields, 1);
        }
      }
    }
  }

  /** Runs the handler for one stream entry; on success acks, on failure leaves it pending for reclaim. */
  private async processEntry(
    conn: RedisLike,
    key: string,
    sub: Subscription,
    id: string,
    fields: string[],
    deliveryCount: number,
  ): Promise<void> {
    const idx = fields.indexOf('envelope');
    const raw = idx >= 0 ? fields[idx + 1] : undefined;
    if (!raw) return;
    if (deliveryCount > this.maxDeliveries) {
      await this.deadLetter(conn, key, sub, id, raw, deliveryCount);
      return;
    }
    try {
      const envelope = JSON.parse(raw) as EventEnvelope;
      await sub.handler(envelope);
      await conn.xack(key, sub.group, id);
    } catch (err) {
      // Handler threw — do NOT ack, leave the message pending. Reclaimed
      // via XAUTOCLAIM on the next reclaim tick; dead-lettered once
      // `maxDeliveries` is exceeded.
      this.logger.error(
        { err, key, id, deliveryCount },
        '[RedisStreamsEventBus] handler threw, leaving message pending',
      );
    }
  }

  /** Moves an entry that exhausted its delivery attempts to the dead-letter stream and acks the original. */
  private async deadLetter(
    conn: RedisLike,
    key: string,
    sub: Subscription,
    id: string,
    rawEnvelope: string,
    deliveryCount: number,
  ): Promise<void> {
    const dlq = dlqKeyFor(key);
    try {
      await conn.xadd(
        dlq,
        'MAXLEN',
        '~',
        String(this.maxLen),
        '*',
        'envelope',
        rawEnvelope,
        'error',
        `exceeded maxDeliveries (${this.maxDeliveries})`,
        'deliveryCount',
        String(deliveryCount),
        'sourceKey',
        key,
        'sourceId',
        id,
      );
    } catch (err) {
      // Leave the entry pending so it is retried rather than lost.
      this.logger.error({ err, key, id }, '[RedisStreamsEventBus] dead-letter write failed');
      return;
    }
    await conn.xack(key, sub.group, id);
    this.logger.warn(
      { key, id, deliveryCount, dlq },
      '[RedisStreamsEventBus] moved message to dead-letter stream after exhausting deliveries',
    );
  }

  /** Reclaims entries left pending by a crashed/failed consumer (idle >= `minIdleMs`) and re-runs them. */
  private async reclaimStale(conn: RedisLike, key: string, sub: Subscription): Promise<void> {
    let cursor = '0-0';
    for (;;) {
      let claimed: unknown;
      try {
        claimed = await conn.xautoclaim(
          key,
          sub.group,
          sub.consumer,
          this.minIdleMs,
          cursor,
          'COUNT',
          10,
        );
      } catch (err) {
        this.logger.error({ err, key }, '[RedisStreamsEventBus] xautoclaim failed');
        return;
      }
      const [nextCursor, entries] = claimed as [string, Array<[string, string[]]>, string[]?];
      if (!entries || entries.length === 0) return;

      const counts = await this.deliveryCounts(
        conn,
        key,
        sub.group,
        entries.map(([id]) => id),
      );
      for (const [id, fields] of entries) {
        await this.processEntry(conn, key, sub, id, fields, counts.get(id) ?? 1);
      }

      cursor = nextCursor;
      if (cursor === '0-0' || entries.length < 10) return;
    }
  }

  /** `XPENDING` lookup for the delivery count of specific entries (post-reclaim). */
  private async deliveryCounts(
    conn: RedisLike,
    key: string,
    group: string,
    ids: string[],
  ): Promise<Map<string, number>> {
    const counts = new Map<string, number>();
    if (ids.length === 0) return counts;
    // One exact-range lookup per id, so the count is found however many
    // other entries are pending.
    for (const id of ids) {
      try {
        const rows = ((await conn.xpending(key, group, 'IDLE', 0, id, id, 1)) ?? []) as Array<
          [string, string, number, number]
        >;
        const row = rows[0];
        if (row && row[0] === id) counts.set(id, row[3]);
      } catch (err) {
        this.logger.error({ err, key, id }, '[RedisStreamsEventBus] xpending failed');
      }
    }
    return counts;
  }

  async ping(): Promise<void> {
    await this.publisher.ping();
  }

  /**
   * Stops every read loop and closes the connections. A loop only
   * re-checks the closing flag once its current `XREADGROUP BLOCK`
   * returns, so this can take up to `blockMs`.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.closing = true;
    await Promise.allSettled(this.loops);
    await Promise.allSettled(
      Array.from(this.subscriberConns).map((c) => c.quit().catch(() => undefined)),
    );
    await this.publisher.quit().catch(() => undefined);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
