/**
 * Integration-service client — server-to-server caller for
 * `POST /v1/integrations/:integrationId/remediation`.
 *
 * Mints a short-lived HS256 internal token per call and sends the tenant
 * header — mirrors `cost-intelligence/src/inventory/http.provider.ts`.
 * Non-2xx responses never surface the upstream body: the error message is
 * a bare status so no GitHub/integration payload leaks into agent results.
 * The request carries a 15s abort so a hung integration-service fails the
 * `remediation.apply` task instead of pinning it in `running` forever.
 */
import { signAccessToken, type Logger, type ServiceConfig } from '@aicc/shared';
import type { ApplyResult } from '../agents/remediation.js';

interface RemediationResponse {
  opened: boolean;
  kind: 'issue' | 'pull_request';
  url?: string;
  number?: number;
  message: string;
}

const REQUEST_TIMEOUT_MS = 15_000;

export function createIntegrationClient(
  cfg: ServiceConfig,
  logger: Logger,
): (tenantId: string, body: unknown) => Promise<ApplyResult> {
  // Default matches `defaultPort('integration-service')` in @aicc/shared.
  const baseUrl = (process.env.INTEGRATION_SERVICE_URL ?? 'http://127.0.0.1:3006').replace(
    /\/+$/,
    '',
  );

  return async (tenantId: string, body: unknown): Promise<ApplyResult> => {
    const { integrationId, ...payload } = body as Record<string, unknown> & {
      integrationId?: unknown;
    };
    const id = typeof integrationId === 'string' ? integrationId : '';
    const url = `${baseUrl}/v1/integrations/${encodeURIComponent(id)}/remediation`;
    // ponytail: minted per-call (HMAC only, cheap) rather than cached —
    // revisit with a short-lived cache if this becomes hot.
    const token = signAccessToken(
      { sub: 'system:agent-service', role: 'platform_admin', tenantId },
      { ...cfg.auth, ttlSeconds: 60 },
    );
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-tenant-id': tenantId,
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      // An abort/timeout must be distinguishable from the HTTP failure
      // below — never report it as a bare status.
      if (err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
        logger.warn(
          { url, timeoutMs: REQUEST_TIMEOUT_MS },
          'integration-service remediation request timed out',
        );
        throw new Error(
          `integration-service remediation request timed out after ${REQUEST_TIMEOUT_MS}ms`,
          { cause: err },
        );
      }
      throw err;
    }
    if (!res.ok) {
      logger.warn({ url, status: res.status }, 'integration-service remediation request failed');
      throw new Error(`integration-service remediation request failed: ${res.status}`);
    }
    const data = (await res.json()) as RemediationResponse;
    return {
      applied: data.opened === true,
      integrationId: id,
      kind: data.kind,
      url: data.url,
      number: data.number,
      message: data.message,
    };
  };
}
