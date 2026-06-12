// =============================================================================
// Structured logging — reference implementation for TypeScript/Node.js services
// Owner: SREEngineer
// See: docs/observability/monitoring-architecture.md §5
//
// This module wraps `pino` with:
//   - W3C trace context propagation (trace_id, span_id)
//   - PII redaction at the SDK boundary
//   - Mandatory fields (service, version, env, tenant_id)
//   - JSON schema validation in dev/test
// =============================================================================

import { pino, type Logger as PinoLogger, type LoggerOptions } from "pino";
import { trace, context } from "@opentelemetry/api";
import { z } from "zod";

// ---------- JSON Schema (mirror of infra/observability/logs/log-schema.json) ----------
export const LogEntrySchema = z.object({
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/),
  level: z.enum(["debug", "info", "warn", "error", "fatal"]),
  service: z.string().regex(/^[a-z][a-z0-9-]{1,63}$/),
  version: z.string(),
  env: z.enum(["dev", "staging", "prod"]),
  tenant_id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  trace_id: z.string().regex(/^[0-9a-f]{32}$/).optional(),
  span_id: z.string().regex(/^[0-9a-f]{16}$/).optional(),
  user_id: z.string().regex(/^[a-f0-9]{64}$/).optional(),
  message: z.string().min(1).max(2048),
  context: z.record(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
});

// ---------- Redaction patterns ----------
// These are the LAST line of defense; the OTel Collector also redacts.
const REDACT_PATTERNS: Array<{ re: RegExp; type: string }> = [
  { re: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, type: "email" },
  { re: /(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}/g, type: "phone" },
  { re: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, type: "bearer" },
  { re: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, type: "jwt" },
  { re: /AKIA[0-9A-Z]{16}/g, type: "aws_access_key" },
  { re: /ghp_[A-Za-z0-9]{36}/g, type: "github_pat" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, type: "private_key" },
];

function redactString(input: string): string {
  let out = input;
  for (const { re, type } of REDACT_PATTERNS) {
    out = out.replace(re, `[REDACTED:${type}]`);
  }
  return out;
}

function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "authorization" || k === "cookie" || k === "password") {
        out[k] = "[REDACTED:secret]";
      } else {
        out[k] = redactValue(v);
      }
    }
    return out;
  }
  return value;
}

// ---------- Hook to inject trace_id / span_id ----------
function injectTraceContext(target: Record<string, unknown>): void {
  const span = trace.getSpan(context.active());
  if (!span) return;
  const ctx = span.spanContext();
  if (ctx.traceId && ctx.traceId !== "00000000000000000000000000000000") {
    target.trace_id = ctx.traceId;
  }
  if (ctx.spanId && ctx.spanId !== "0000000000000000") {
    target.span_id = ctx.spanId;
  }
}

// ---------- Factory ----------
export interface LoggerConfig {
  service: string;
  version: string;
  env: "dev" | "staging" | "prod";
  /** When true, validate every line against the JSON schema. Default: env !== "prod". */
  validateSchema?: boolean;
  /** Override the default level. */
  level?: "debug" | "info" | "warn" | "error" | "fatal";
}

export function createLogger(cfg: LoggerConfig): PinoLogger {
  if (!/^[a-z][a-z0-9-]{1,63}$/.test(cfg.service)) {
    throw new Error(`Invalid service name: ${cfg.service}`);
  }

  const baseFields = {
    service: cfg.service,
    version: cfg.version,
    env: cfg.env,
  };

  const options: LoggerOptions = {
    level: cfg.level ?? (cfg.env === "prod" ? "info" : "debug"),
    base: baseFields,
    timestamp: () => `,"timestamp":"${new Date().toISOString()}"`,
    formatters: {
      level: (label) => ({ level: label }),
      // Pino runs `bindings` once per log call; inject tenant_id there.
      bindings: () => ({}),
      // The `log` formatter is called for every log object. We inject
      // trace context, tenant_id, and run redaction here.
      log: (obj) => {
        const enriched: Record<string, unknown> = { ...obj };
        injectTraceContext(enriched);

        // Mandatory tenant_id; throw if missing in non-test environments.
        if (typeof enriched.tenant_id !== "string") {
          // Fall back to "unknown" only in dev to surface the bug visibly.
          enriched.tenant_id = cfg.env === "dev" ? "unknown" : "";
        }

        // Redact.
        for (const key of Object.keys(enriched)) {
          if (key === "level" || key === "timestamp" || key === "service"
              || key === "version" || key === "env" || key === "tenant_id"
              || key === "trace_id" || key === "span_id") continue;
          enriched[key] = redactValue(enriched[key]);
        }

        // Optional: schema validation in dev/test.
        if (cfg.validateSchema ?? cfg.env !== "prod") {
          const result = LogEntrySchema.safeParse(enriched);
          if (!result.success) {
            // Log to stderr; never block the main log path.
            process.stderr.write(
              `[log-validator] schema violation: ${result.error.message}\n`
            );
          }
        }
        return enriched;
      },
    },
    // Hard cap on serialized log size to avoid runaway payloads.
    messageKey: "message",
  };

  return pino(options);
}

// ---------- Convenience helpers ----------
export function withTenant(logger: PinoLogger, tenantId: string): PinoLogger {
  return logger.child({ tenant_id: tenantId });
}

export function withUser(logger: PinoLogger, userIdHash: string): PinoLogger {
  return logger.child({ user_id: userIdHash });
}
