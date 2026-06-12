// =============================================================================
// Health check endpoints — reference implementation for Fastify/Node.js
// Owner: SREEngineer
// See: docs/observability/monitoring-architecture.md §6
//
// Exposes /livez, /readyz, /startz on a separate management port.
// /readyz performs deep dependency checks with per-check timeouts.
// =============================================================================

import Fastify, { type FastifyInstance } from "fastify";
import { setTimeout as sleep } from "node:timers/promises";

export interface HealthCheck {
  /** Stable identifier of the dependency. Becomes a key in the response. */
  name: string;
  /** Runs the check. Must reject or throw on failure. */
  run: () => Promise<{ ok: boolean; latencyMs: number; detail?: string }>;
  /** Whether the check is required for readiness. */
  required: boolean;
  /** Per-check timeout in ms. */
  timeoutMs?: number;
}

export interface HealthCheckOptions {
  service: string;
  version: string;
  startedAt: Date;
  checks: HealthCheck[];
  /** Default per-check timeout. */
  defaultTimeoutMs?: number;
}

export function buildHealthServer(opts: HealthCheckOptions): FastifyInstance {
  const app = Fastify({ logger: false });
  const defaultTimeout = opts.defaultTimeoutMs ?? 250;
  const startCompleted = { value: false };

  // ---------- Liveness: shallow, never checks dependencies ----------
  app.get("/livez", async () => {
    return { status: "ok", service: opts.service, version: opts.version };
  });

  // ---------- Startup: returns ok after the first successful /readyz ----------
  app.get("/startz", async (_req, reply) => {
    if (!startCompleted.value) {
      return reply.code(503).send({ status: "starting" });
    }
    return { status: "ok" };
  });

  // ---------- Readiness: deep check of all dependencies ----------
  app.get("/readyz", async (_req, reply) => {
    const results: Record<string, unknown> = {};
    let allOk = true;
    let anyRequiredFailed = false;

    const checks = await Promise.all(
      opts.checks.map(async (check) => {
        const timeoutMs = check.timeoutMs ?? defaultTimeout;
        const started = Date.now();
        try {
          const result = await Promise.race([
            check.run(),
            sleep(timeoutMs).then(() => {
              throw new Error(`timeout after ${timeoutMs}ms`);
            }),
          ]);
          const entry = {
            status: result.ok ? "ok" : "fail",
            latency_ms: result.latencyMs ?? Date.now() - started,
            ...(result.detail ? { detail: result.detail } : {}),
          };
          if (!result.ok) {
            allOk = false;
            if (check.required) anyRequiredFailed = true;
          }
          return [check.name, entry] as const;
        } catch (err) {
          const entry = {
            status: "fail",
            latency_ms: Date.now() - started,
            detail: err instanceof Error ? err.message : String(err),
          };
          allOk = false;
          if (check.required) anyRequiredFailed = true;
          return [check.name, entry] as const;
        }
      })
    );

    for (const [name, entry] of checks) {
      results[name] = entry;
    }

    if (allOk) startCompleted.value = true;

    return reply
      .code(anyRequiredFailed ? 503 : 200)
      .send({
        status: anyRequiredFailed ? "fail" : "ok",
        checks: results,
        version: opts.version,
        uptime_s: Math.floor((Date.now() - opts.startedAt.getTime()) / 1000),
      });
  });

  return app;
}

// ---------- Example: dependency check builders ----------
import pg from "pg";
import { createClient as createRedisClient } from "redis";
import { connect as connectNats } from "nats";

export const postgresCheck = (pool: pg.Pool, required = true): HealthCheck => ({
  name: "postgres",
  required,
  run: async () => {
    const started = Date.now();
    const r = await pool.query("SELECT 1");
    return { ok: r.rowCount === 1, latencyMs: Date.now() - started };
  },
});

export const redisCheck = (
  client: ReturnType<typeof createRedisClient>,
  required = true
): HealthCheck => ({
  name: "redis",
  required,
  run: async () => {
    const started = Date.now();
    const pong = await client.ping();
    return { ok: pong === "PONG", latencyMs: Date.now() - started };
  },
});

export const natsCheck = (
  nc: Awaited<ReturnType<typeof connectNats>>,
  required = true
): HealthCheck => ({
  name: "nats",
  required,
  run: async () => {
    const started = Date.now();
    if (nc.isClosed()) return { ok: false, latencyMs: 0, detail: "closed" };
    // Round-trip ping with a short timeout is the canonical NATS health check.
    await nc.request("health.ping", undefined, { timeout: 200 });
    return { ok: true, latencyMs: Date.now() - started };
  },
});
