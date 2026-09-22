# 0014 — Redis Streams event bus driver

Status: accepted
Date: 2026-09-22

## Context

Every service published/subscribed through `@aicc/shared`'s
`InMemoryEventBus` (S1) — an in-process `Map<type, Set<handler>>`.
Fine for a single-process dev stack and tests, but it doesn't survive
a service restart, doesn't cross a process boundary, and the
"finalize the Redis Streams / NATS implementation" TODO in
`events/index.ts` had sat unresolved since Sprint 1. `docker-compose.yml`
already runs a `redis` container and six services (`auth`, `agent`,
`security`, `incident`, `compliance`, `integration` — the ones that
actually publish or subscribe today) already `depends_on` it, unused.

## Decision

- **Redis Streams, not pub/sub.** `XADD`/`XREADGROUP` give durability
  (events survive in the stream after delivery, up to `MAXLEN`) and
  at-least-once delivery with acks; Redis pub/sub gives neither — a
  subscriber that's down loses the message.
- **One stream per event type, one consumer group per service.**
  Stream key `aicc:events:<type>` (sanitised). Group name = service
  name, so every subscribing service gets its own copy of every event
  on that stream (fan-out via groups) — exactly the semantics
  `InMemoryEventBus`'s `Set<handler>`-per-type already gave every
  service in-process. Consumer name is
  `<service>-<pid>-<random>` so multiple replicas of one service share
  the group's cursor without double-processing.
- **At-least-once, no ack on handler failure.** A handler that throws
  leaves its message pending (`XACK` skipped) rather than dropping it
  or retrying inline. Deferred: no dead-letter queue and no
  `XAUTOCLAIM`-based reclaim of a crashed consumer's pending entries —
  today they sit pending until reclaimed by hand. Add
  `XAUTOCLAIM` reclaim if this becomes an operational problem.
- **Trimming can drop unacked entries.** `XADD ... MAXLEN ~ 10000`
  trims by length, not by pending state, so a stream that keeps
  growing while a consumer is down or failing will eventually evict
  entries that are still in that group's pending list. At-least-once
  therefore holds only while a consumer keeps up with roughly the
  last 10k events per type. Raise `maxLen`, or trim by age with
  `MINID` once retention requirements are known.
- **One factory, `createEventBus({ driver, redisUrl, serviceName, logger })`.**
  `EVENT_BUS_DRIVER=memory` (default) or `redis`; `REDIS_URL` required
  for the latter. `loadServiceConfig()` reads both into `cfg.eventBus`.
  Every service does
  `deps?.bus ?? createEventBus({ ...cfg.eventBus, serviceName: SERVICE_NAME, logger })`
  — switching drivers is an env var, never a code change. `sealEnvelope()`
  (fills `eventId`/`occurredAt`) is shared by both implementations so
  they can't drift on envelope shape.
- **`ioredis` (MIT), not a hand-rolled client.** Two connections per
  bus instance are required by ioredis's blocking-command model: one
  for `XADD`/`XGROUP`/`PING` (the "publisher"), one duplicated
  (`.duplicate()`) per `subscribe()` call for the blocking
  `XREADGROUP` loop, so a slow/absent subscriber never blocks publish.
- **`ping()` on the bus for `/readyz`.** `EventBus.ping?()` is optional
  — `InMemoryEventBus` omits it, `RedisStreamsEventBus` implements it
  with a plain `PING`. The six redis-wired services' `/readyz` probes
  it the same way `incident`/`kubernetes` already probe Postgres:
  probe fails → `503`.
- **Deferred (not in this cut):** dead-letter queue, `XAUTOCLAIM` of
  stale pending entries, trimming that respects pending entries, cross-stream ordering guarantees (Streams
  only order within one key), and any schema registry for envelope
  payloads. None of these block the S6-3 goal (a real, restart-durable
  transport behind the existing `EventBus` interface); all are
  additive later.

## Consequences

- Docker compose: `auth`, `agent`, `security`, `incident`,
  `compliance`, `integration` set `EVENT_BUS_DRIVER=redis` +
  `REDIS_URL=redis://redis:6379`. The other seven services (no
  publish/subscribe today — `kubernetes`, `k8s-health`,
  `runtime-security`, `inventory`, `cost-intelligence`, `topology`,
  `reporting`) stay on the `memory` default; wiring them to redis is a
  one-line env change whenever they start using the bus.
- `EVENT_BUS_DRIVER` unset (local/non-docker dev, all existing tests)
  behaves exactly as before S6-3 — `createEventBus` returns
  `InMemoryEventBus` and no service's behaviour changes.
