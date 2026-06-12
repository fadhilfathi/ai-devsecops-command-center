// POA&M HTTP routes
//
// Endpoints:
//   POST  /poam                  — manual create
//   GET   /poam                  — list (supports ?status=open|closed|overdue|...)
//   GET   /poam/:id              — get one
//   POST  /poam/:id/start        — open -> in_progress
//   POST  /poam/:id/await-evidence — open|in_progress -> awaiting_evidence
//   POST  /poam/:id/close        — -> closed (requires evidence)
//   POST  /poam/:id/accept-risk  — -> risk_accepted (justification + expiry)
//
// All routes are tenant-scoped. The tenant id is read from the
// `x-tenant-id` request header (set by the auth gateway). The user id
// is read from `x-user-id`. Both are required; missing values return
// 401.

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { NotFoundError, AppError, type Logger } from '@aicc/shared';
import type { Framework } from '@aicc/shared/types/domain';
import { PoamService, type PoamStatus } from '../poam/index.js';

const CreatePoamSchema = z.object({
  controlId: z.string().min(1).max(64),
  framework: z.enum(['cis_v8', 'nist_800_53', 'soc2', 'iso_27001']),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(2000),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  slaDays: z.number().int().positive().max(365).optional(),
  vulnId: z.string().min(1).max(64).optional(),
  metadata: z.record(z.unknown()).optional(),
});

const ClosePoamSchema = z.object({
  resolutionNotes: z.string().min(1).max(2000),
  evidenceRefs: z.array(z.string().min(1)).min(1),
});

const AcceptRiskSchema = z.object({
  justification: z.string().min(20).max(2000),
  expiresAt: z.string().datetime(),
  compensatingControlId: z.string().min(1).max(64).optional(),
});

const ListQuerySchema = z.object({
  status: z.enum(['open', 'closed', 'overdue', 'in_progress', 'awaiting_evidence', 'risk_accepted', 'all']).optional(),
  controlId: z.string().optional(),
  framework: z.enum(['cis_v8', 'nist_800_53', 'soc2', 'iso_27001']).optional(),
  vulnId: z.string().optional(),
  dueBefore: z.string().datetime().optional(),
  dueAfter: z.string().datetime().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export interface PoamRoutesDeps {
  poamService: PoamService;
  logger: Logger;
}

function requireTenantUser(req: FastifyRequest): { tenantId: string; userId: string } {
  const tenantId = req.headers['x-tenant-id'];
  const userId = req.headers['x-user-id'];
  if (typeof tenantId !== 'string' || !tenantId) {
    throw new AppError('UNAUTHORIZED', 'Missing x-tenant-id header', 401);
  }
  if (typeof userId !== 'string' || !userId) {
    throw new AppError('UNAUTHORIZED', 'Missing x-user-id header', 401);
  }
  return { tenantId, userId };
}

export const buildPoamRoutes: FastifyPluginAsync<PoamRoutesDeps> = async (app, deps) => {
  const { poamService, logger } = deps;

  // POST /v1/poam
  app.post('/poam', async (req, reply) => {
    const { tenantId, userId } = requireTenantUser(req);
    const parsed = CreatePoamSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError('VALIDATION_ERROR', 'Invalid POA&M body', 400, parsed.error.flatten());
    }
    const poam = await poamService.createManual(tenantId, parsed.data, userId);
    reply.code(201).send(poam);
  });

  // GET /v1/poam
  app.get('/poam', async (req) => {
    const { tenantId } = requireTenantUser(req);
    const parsed = ListQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      throw new AppError('VALIDATION_ERROR', 'Invalid query', 400, parsed.error.flatten());
    }
    return poamService.list(tenantId, parsed.data);
  });

  // GET /v1/poam/:id
  app.get<{ Params: { id: string } }>('/poam/:id', async (req) => {
    const { tenantId } = requireTenantUser(req);
    const poam = await poamService.get(tenantId, req.params.id);
    if (!poam) throw new NotFoundError('PoamItem', req.params.id);
    return poam;
  });

  // POST /v1/poam/:id/start
  app.post<{ Params: { id: string } }>('/poam/:id/start', async (req) => {
    const { tenantId, userId } = requireTenantUser(req);
    return poamService.startProgress(tenantId, req.params.id, userId);
  });

  // POST /v1/poam/:id/await-evidence
  app.post<{ Params: { id: string } }>('/poam/:id/await-evidence', async (req) => {
    const { tenantId, userId } = requireTenantUser(req);
    return poamService.markAwaitingEvidence(tenantId, req.params.id, userId);
  });

  // POST /v1/poam/:id/close
  app.post<{ Params: { id: string } }>('/poam/:id/close', async (req) => {
    const { tenantId, userId } = requireTenantUser(req);
    const parsed = ClosePoamSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError('VALIDATION_ERROR', 'Invalid close body', 400, parsed.error.flatten());
    }
    try {
      return await poamService.close(tenantId, req.params.id, userId, parsed.data.resolutionNotes, parsed.data.evidenceRefs);
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes('requires at least one evidence')) {
        throw new AppError('VALIDATION_ERROR', msg, 400);
      }
      if (msg.includes('not found')) throw new NotFoundError('PoamItem', req.params.id);
      if (msg.includes('Invalid')) throw new AppError('VALIDATION_ERROR', msg, 400);
      logger.error({ err, poamId: req.params.id }, 'poam_close_failed');
      throw err;
    }
  });

  // POST /v1/poam/:id/accept-risk
  app.post<{ Params: { id: string } }>('/poam/:id/accept-risk', async (req) => {
    const { tenantId, userId } = requireTenantUser(req);
    const parsed = AcceptRiskSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError('VALIDATION_ERROR', 'Invalid accept-risk body', 400, parsed.error.flatten());
    }
    try {
      return await poamService.acceptRisk(
        tenantId,
        req.params.id,
        userId,
        parsed.data.justification,
        parsed.data.expiresAt,
        parsed.data.compensatingControlId,
      );
    } catch (err) {
      const msg = (err as Error).message;
      if (msg.includes('not found')) throw new NotFoundError('PoamItem', req.params.id);
      if (msg.includes('Invalid')) throw new AppError('VALIDATION_ERROR', msg, 400);
      throw err;
    }
  });
};

export type { PoamStatus, Framework };
