import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EventTypes, NotFoundError, type EventBus, type Logger, type UUID } from '@aicc/shared';
import type { AssetRepository } from '../repositories/asset.repository.js';
import type { ScanRepository } from '../repositories/scan.repository.js';
import type { FindingRepository } from '../repositories/finding.repository.js';

interface Deps {
  logger: Logger;
  assets: AssetRepository;
  scans: ScanRepository;
  findings: FindingRepository;
  bus: EventBus;
}

const StartScanSchema = z.object({
  assetId: z.string().uuid(),
  scanner: z.enum(['trivy', 'grype', 'syft']).default('trivy'),
});

const FindingSeedSchema = z.object({
  cveId: z.string().optional(),
  packageName: z.string().optional(),
  packageVersion: z.string().optional(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  title: z.string().min(1),
  description: z.string().min(1),
  remediation: z.string().optional(),
});

const CompleteScanSchema = z.object({
  findings: z.array(FindingSeedSchema).default([]),
});

export const buildScanRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, assets, scans, findings, bus } = opts;

  server.get('/v1/scans', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const items = await scans.list(tenantId);
    return { items, total: items.length };
  });

  server.post('/v1/scans', async (req, reply) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    if (!tenantId) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: 'x-tenant-id header required' };
    }
    const body = StartScanSchema.parse(req.body);
    const asset = await assets.findById(body.assetId, tenantId);
    if (!asset) throw new NotFoundError('Asset', body.assetId);

    const scan = await scans.create({ assetId: body.assetId, tenantId: tenantId as UUID, scanner: body.scanner });
    await bus.publish({
      type: EventTypes.SCAN_STARTED,
      version: 1,
      source: 'security-service',
      tenantId,
      severity: 'info',
      data: { scanId: scan.id, assetId: asset.id, scanner: scan.scanner },
    });

    // Sprint 1: synchronously mark as succeeded with empty findings.
    // Sprint 2 will dispatch to a worker running Trivy/Grype.
    await scans.updateStatus(scan.id, 'succeeded');
    await bus.publish({
      type: EventTypes.SCAN_COMPLETED,
      version: 1,
      source: 'security-service',
      tenantId,
      severity: 'info',
      data: { scanId: scan.id, assetId: asset.id, findingsCount: 0 },
    });

    reply.code(202).send({ scan });
  });

  server.post<{ Params: { id: string } }>('/v1/scans/:id/complete', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const body = CompleteScanSchema.parse(req.body);
    const scan = await scans.findById(req.params.id, tenantId);
    if (!scan) throw new NotFoundError('Scan', req.params.id);

    const created = [];
    for (const seed of body.findings) {
      const f = await findings.create({ ...seed, scanId: scan.id, tenantId: tenantId as UUID });
      created.push(f);
      await bus.publish({
        type: EventTypes.VULNERABILITY_DETECTED,
        version: 1,
        source: 'security-service',
        tenantId,
        severity: f.severity,
        data: { findingId: f.id, scanId: scan.id, severity: f.severity, cveId: f.cveId },
      });
    }
    await scans.updateStatus(scan.id, 'succeeded');
    await bus.publish({
      type: EventTypes.SCAN_COMPLETED,
      version: 1,
      source: 'security-service',
      tenantId,
      severity: 'info',
      data: { scanId: scan.id, findingsCount: created.length },
    });
    return { scan: await scans.findById(scan.id, tenantId), findings: created };
  });

  server.get<{ Params: { id: string } }>('/v1/scans/:id', async (req) => {
    const tenantId = req.headers['x-tenant-id'] as string;
    const scan = await scans.findById(req.params.id, tenantId);
    if (!scan) throw new NotFoundError('Scan', req.params.id);
    return { scan };
  });

  logger.debug('security-service scan routes registered');
};
