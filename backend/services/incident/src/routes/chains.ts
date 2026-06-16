/**
 * Chain routes — AI incident correlation.
 *
 *   GET /v1/incidents/chains
 *   GET /v1/incidents/chains/:id
 *   GET /v1/incidents/chains/edges
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { type Logger, type UUID } from '@aicc/shared';
import type { IncidentChain, CorrelationEdge } from '../correlation/correlation-engine.js';
import type { ChainRepository } from '../correlation/chain.repository.js';

interface Deps { logger: Logger; chains: ChainRepository; }

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

export const buildChainRoutes: FastifyPluginAsync<Deps> = async (server: FastifyInstance, opts) => {
  const { logger, chains } = opts;

  server.get('/v1/incidents/chains', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const items = await chains.list(tenantId);
    return { items, total: items.length };
  });

  server.get<{ Params: { id: string } }>('/v1/incidents/chains/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const chain = await chains.findById(req.params.id, tenantId);
    if (!chain) {
      const e = new Error('chain not found') as Error & { statusCode?: number };
      e.statusCode = 404;
      throw e;
    }
    return { chain };
  });

  server.get('/v1/incidents/chains/edges/all', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const items: CorrelationEdge[] = await chains.edgesFor(tenantId);
    return { items, total: items.length };
  });

  logger.debug('incident-service chain routes registered');
};
