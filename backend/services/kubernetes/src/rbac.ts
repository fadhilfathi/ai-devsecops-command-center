/**
 * Shared `platform_admin` gate.
 *
 * Any route that stores or exercises live API server credentials (cluster
 * onboarding, credential rotation, connection testing) is a platform-level
 * operation restricted to `platform_admin`, matching the RBAC convention in
 * `security-service`'s `middleware/rbac.ts`.
 */
import type { preHandlerHookHandler } from 'fastify';
import { ForbiddenError, UnauthorizedError } from '@aicc/shared';

export const requireAdmin: preHandlerHookHandler = async (req) => {
  if (!req.userRole) throw new UnauthorizedError('Authentication required');
  if (req.userRole !== 'platform_admin') {
    throw new ForbiddenError(`Requires role 'platform_admin'; got '${req.userRole}'`);
  }
};
