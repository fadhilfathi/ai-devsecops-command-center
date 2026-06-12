// =============================================================================
// OpenTelemetry bootstrap — reference implementation for backend services
// Owner: SREEngineer
// See: docs/observability/monitoring-architecture.md §3, §7
//
// Initializes:
//   - Resource attributes (service.name, service.version, deployment.environment)
//   - Trace exporter (OTLP gRPC -> OTel Collector)
//   - Metric exporter (OTLP -> Collector)
//   - Log exporter (OTLP -> Collector) — pino bridge
//   - Auto-instrumentations for HTTP, Fastify, Postgres, Redis, NATS
// =============================================================================

import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-grpc";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-grpc";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-grpc";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { diag, DiagConsoleLogger, DiagLogLevel } from "@opentelemetry/api";

if (process.env.OTEL_LOG_LEVEL === "debug") {
  diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.DEBUG);
}

export interface OtelBootstrapOptions {
  service: string;
  version: string;
  env: "dev" | "staging" | "prod";
  /** Endpoint of the OTel Collector. Default: http://localhost:4317 */
  endpoint?: string;
}

let sdk: NodeSDK | null = null;

export function startOtel(opts: OtelBootstrapOptions): void {
  const endpoint = opts.endpoint ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4317";

  sdk = new NodeSDK({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: opts.service,
      [ATTR_SERVICE_VERSION]: opts.version,
      "deployment.environment": opts.env,
      "service.namespace": "ai-devsecops",
      "tenant.id": process.env.TENANT_ID ?? "default",
    }),

    traceExporter: new OTLPTraceExporter({ url: `${endpoint}` }),
    metricExporter: new OTLPMetricExporter({ url: `${endpoint}` }),
    logRecordProcessor: undefined, // log exporter is wired in via the pino bridge

    instrumentations: [
      getNodeAutoInstrumentations({
        "@opentelemetry/instrumentation-fs": { enabled: false }, // disable fs spam
        "@opentelemetry/instrumentation-http": {
          // Don't trace /livez, /readyz, /startz, /metrics
          ignoreIncomingRequestHook: (req) => {
            const url = req.url ?? "";
            return url === "/livez" || url === "/readyz" || url === "/startz" || url === "/metrics";
          },
        },
        "@opentelemetry/instrumentation-pg": { enabled: true },
        "@opentelemetry/instrumentation-ioredis": { enabled: true },
        "@opentelemetry/instrumentation-nats": { enabled: true },
      }),
    ],
  });

  sdk.start();
  process.stdout.write(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "info",
      service: opts.service,
      version: opts.version,
      env: opts.env,
      message: `OpenTelemetry started — endpoint=${endpoint}`,
    }) + "\n"
  );
}

export async function shutdownOtel(): Promise<void> {
  if (!sdk) return;
  try {
    await sdk.shutdown();
  } catch (err) {
    process.stderr.write(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: "error",
        message: "OpenTelemetry shutdown failed",
        context: { error: err instanceof Error ? err.message : String(err) },
      }) + "\n"
    );
  }
}

// Graceful shutdown — flush telemetry before exit.
const flush = () => {
  void shutdownOtel().finally(() => process.exit(0));
};
process.on("SIGTERM", flush);
process.on("SIGINT", flush);
