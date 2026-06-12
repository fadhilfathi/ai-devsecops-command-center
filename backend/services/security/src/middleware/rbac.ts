/**
 * Role-based access control (RBAC) middleware.
 *
 * Two layers:
 *   1. `requireAuth` — already provided by `middleware/auth.ts`.
 *   2. `requireRole(...allowed)` — adds a role check on top of `requireAuth`.
 *
 * Roles (per docs/architecture/security-model.md, owned by SecurityArchitect):
 *   - `platform_admin`      — full access (god mode)
 *   - `security_engineer`   — read/write all security data, trigger scans, triage
 *   - `security_analyst`    — read all security data, write triage notes
 *   - `compliance_officer`  — read security data, write compliance evidence
 *   - `developer`           — read security data scoped to own assets
 *   - `viewer`              — read-only dashboard access
 *
 * The Leader's S2.5 spec uses the short form "security-engineer" and
 * "admin" in prose; we map them to `security_engineer` and `platform_admin`
 * in code. The Zod schema accepts both forms and normalises to the
 * canonical underscored form.
 */
import type { FastifyRequest, preHandlerHookHandler } from 'fastify';
import { AppError, type UserRole } from '@aicc/shared';

const ROLE_ALIASES: Record<string, UserRole> = {
  admin: 'platform_admin',
  'platform-admin': 'platform_admin',
  'security-engineer': 'security_engineer',
  'security_analyst': 'security_analyst',
  'security-analyst': 'security_analyst',
  'compliance-officer': 'compliance_officer',
  'developer': 'developer',
  'viewer': 'viewer',
};

export function normaliseRole(input: string): UserRole {
  const lower = input.toLowerCase();
  const mapped = ROLE_ALIASES[lower];
  if (mapped) return mapped;
  // Fall back to the canonical form if it already matches
  if (lower === 'platform_admin' || lower === 'security_engineer' || lower === 'security_analyst' ||
      lower === 'compliance_officer' || lower === 'developer' || lower === 'viewer') {
    return lower as UserRole;
  }
  throw new AppError('VALIDATION_ERROR', `Unknown role: ${input}`);
}

/**
 * Per-route RBAC: require at least one of the listed roles.
 *
 *   server.post('/sbom/generate', { preHandler: requireRole('platform_admin', 'security_engineer') }, handler);
 */
export function requireRole(...allowed: UserRole[]): preHandlerHookHandler {
  const allowedSet = new Set<UserRole>(allowed);
  return async (req: FastifyRequest) => {
    if (!req.user) {
      throw new AppError('UNAUTHENTICATED', 'Authentication required');
    }
    if (!allowedSet.has(req.user.role)) {
      throw new AppError(
        'FORBIDDEN',
        `Requires one of [${Array.from(allowedSet).join(', ')}]; got '${req.user.role}'`,
        { statusCode: 403, details: { allowed: Array.from(allowedSet), got: req.user.role } },
      );
    }
  };
}

/**
 * Tenant isolation guard: reject any request whose JWT tenantId does
 * not match the `x-tenant-id` header (when present). This prevents
 * a token issued for tenant A from operating on tenant B's data.
 */
export const requireTenantMatch: preHandlerHookHandler = async (req: FastifyRequest) => {
  if (!req.user) throw new AppError('UNAUTHENTICATED', 'Authentication required');
  const headerTenant = req.headers['x-tenant-id'] as string | undefined;
  if (headerTenant && headerTenant !== req.user.tenantId) {
    throw new AppError(
      'FORBIDDEN',
      'Token tenantId does not match x-tenant-id header',
      { statusCode: 403, details: { tokenTenant: req.user.tenantId, headerTenant } },
    );
  }
};
