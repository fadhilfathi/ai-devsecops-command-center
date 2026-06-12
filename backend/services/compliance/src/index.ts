import Fastify from 'fastify';
import {
  registerHealth,
  registerShutdown,
  ServiceConfigSchema,
  createLogger,
} from '@aicc/shared';
import { InMemoryEventBus } from '@aicc/shared/events';
import { loadConfig } from './config.js';
import { buildControlsRoutes } from './routes/controls.js';
import { buildEvidenceRoutes } from './routes/evidence.js';
import { buildFrameworksRoutes } from './routes/frameworks.js';
import { buildPoamRoutes } from './routes/poam.js';
import {
  buildPoamRepository,
  PoamService,
} from './poam/index.js';
import { MappingEngine } from './control-mapper/index.js';
import mappingRules from './control-mapper/mapping-rules.json' with { type: 'json' };
import { InMemoryBlobStore } from './evidence/blob-store.memory.js';
import { EvidenceAttacher } from './evidence/evidence-attacher.js';
import { buildEvidenceRepository } from './repositories/evidence.repository.js';
import { buildScanListener } from './evidence/scan-listener.js';
import { metricsRegistry } from './observability/audit.js';

const config = ServiceConfigSchema.parse(loadConfig());

const logger = createLogger({ service: 'compliance-service', level: config.LOG_LEVEL });
const app = Fastify({ logger });

registerHealth(app, 'compliance-service');
registerShutdown(app);

// ---------------------------------------------------------------------------
// Wire domain services
// ---------------------------------------------------------------------------

const bus = new InMemoryEventBus();

const poamRepo = buildPoamRepository();
const poamService = new PoamService({ repo: poamRepo, bus });

const mappingEngine = new MappingEngine({ rules: mappingRules as any });

const blobStore = new InMemoryBlobStore();
const evidenceRepo = buildEvidenceRepository();
const evidenceAttacher = new EvidenceAttacher({
  store: blobStore,
  evidenceRepo,
  mappingEngine,
  poamService,
  bus,
});

// ---------------------------------------------------------------------------
// HTTP routes
// ---------------------------------------------------------------------------

await app.register(buildControlsRoutes, { prefix: '/v1' });
await app.register(buildEvidenceRoutes, { prefix: '/v1' });
await app.register(buildFrameworksRoutes, { prefix: '/v1' });
await app.register(buildPoamRoutes, { prefix: '/v1', poamService, logger });

// ---------------------------------------------------------------------------
// Bus subscriptions
// ---------------------------------------------------------------------------

const scanListener = buildScanListener(evidenceAttacher);
await bus.subscribe(scanListener.topic, scanListener.handler);

// ---------------------------------------------------------------------------
// Schedulers
// ---------------------------------------------------------------------------

// Overdue POA&M scanner: hourly tick marks past-due open items as 'overdue'.
const ONE_HOUR_MS = 60 * 60 * 1000;
const overdueTimer = setInterval(() => {
  poamService.scanForOverdue().catch((err) => {
    app.log.error({ err }, 'overdue_scan_failed');
  });
}, ONE_HOUR_MS);
overdueTimer.unref();

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

app.get('/metrics', async (_req, reply) => {
  // Flush the local audit registry. Sprint 3 will swap this to the shared
  // @aicc/observability package's metricsRegistry when it lands.
  reply.type('text/plain; version=0.0.4; charset=utf-8');
  return metricsRegistry.metrics();
});

app.listen({ port: config.PORT, host: '0.0.0.0' });
