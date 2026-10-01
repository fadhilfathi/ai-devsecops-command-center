import type { FastifyInstance, FastifyPluginAsync, preHandlerHookHandler } from 'fastify';
import { z } from 'zod';
import {
  AppError,
  EcosystemSchema,
  EventTypes,
  NotFoundError,
  ValidationError,
  type EventBus,
  type Integration,
  type Logger,
  type UUID,
} from '@aicc/shared';
import { decryptSecret, parseKeyring } from '@aicc/shared/crypto';
import type { IntegrationRepository } from '../repositories/integration.repository.js';
import type { SyncRepository } from '../repositories/sync.repository.js';
import type { ProviderRegistry } from '../providers/registry.js';
import { GithubApiError, GithubClient, type GithubRef } from '../providers/github.client.js';

interface Deps {
  logger: Logger;
  integrations: IntegrationRepository;
  providers: ProviderRegistry;
  syncs: SyncRepository;
  bus: EventBus;
}

function requireTenant(tenantId: string): UUID {
  if (!tenantId) {
    const e = new Error('x-tenant-id header required') as Error & { statusCode?: number };
    e.statusCode = 400;
    throw e;
  }
  return tenantId as UUID;
}

/**
 * Role gate for `POST /v1/integrations/:integrationId/remediation` — the
 * only route here with a write side effect on an external system. Mirrors
 * security-service's `requireRole` (not imported: no cross-service imports).
 * `userRole` is undefined only on the `AUTH_DEV_BYPASS` header path (a
 * verified token always carries a required `role` claim and a missing token
 * is 401 otherwise); such requests are let through because dev bypass is
 * dev/test-only and its caller can already forge any tenant — a role gate
 * there would only lock out the e2e smoke.
 */
const requirePlatformAdmin: preHandlerHookHandler = async (req) => {
  if (req.userRole === undefined) return;
  if (req.userRole !== 'platform_admin') {
    throw new AppError('FORBIDDEN', `Requires one of [platform_admin]; got '${req.userRole}'`, {
      statusCode: 403,
      details: { allowed: ['platform_admin'], got: req.userRole },
    });
  }
};

/**
 * Credential disclosure guard. `config` is free-form and accepts any key, so
 * it may hold live credentials (a GitHub PAT under `config.token`/`config.pat`
 * since S11-2) — returning it verbatim defeats the at-rest encryption against
 * any read-capable tenant user. Every route response MUST pass through here.
 * Pure and exported for unit tests. `owner`/`repo` are not secrets and the
 * frontend needs them; only sensitive-looking keys are masked.
 */
const SENSITIVE_KEY = /token|secret|pat|password|api[-_]?key|credential/i;

export function redactIntegration(i: Integration): Integration {
  const config: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(i.config)) config[k] = SENSITIVE_KEY.test(k) ? '***' : v;
  return { ...i, config };
}

const CreateIntegrationSchema = z.object({
  provider: z.enum(['github', 'gitlab', 'bitbucket', 'jira', 'slack']),
  name: z.string().min(1).max(200),
  config: z.record(z.string(), z.unknown()).default({}),
  enabled: z.boolean().default(true),
});

const RemediationRequestSchema = z.object({
  proposal: z.object({
    package: z.object({
      name: z.string().min(1).max(200),
      // Single source of truth in @aicc/shared (same enum the agent-side
      // remediation module uses) — see `EcosystemSchema` in
      // backend/packages/shared/src/types/domain.ts.
      ecosystem: EcosystemSchema,
    }),
    from: z.string().min(1).max(200),
    to: z.string().min(1).max(200),
    bump: z.enum(['none', 'patch', 'minor', 'major', 'unknown']),
    resolves: z.array(z.string().max(200)),
    risk: z.enum(['low', 'medium', 'high']),
    // Every interpolated field is bounded, and `manifestHint` may not carry a
    // code fence: it is spliced into a real GitHub issue body, so a ``` run
    // would break out and inject arbitrary rendered markdown/@mentions into
    // the tenant's production repository. The renderer additionally fences it
    // with four backticks as belt and braces.
    manifestHint: z
      .string()
      .max(2000)
      .refine((s) => !s.includes('```'), {
        message: 'manifestHint must not contain ``` (code fence)',
      }),
    status: z.enum(['ok', 'manual_review']),
  }),
  context: z
    .object({
      findingId: z.string().max(200).optional(),
      cveId: z.string().max(200).optional(),
      assetId: z.string().max(200).optional(),
      repo: z.string().max(200).optional(),
    })
    .optional(),
  dryRun: z.boolean().optional(),
});

export type RemediationProposal = z.infer<typeof RemediationRequestSchema>['proposal'];
export type RemediationContext = z.infer<typeof RemediationRequestSchema>['context'];

export type RemediationKind = 'issue' | 'pull_request';

export interface RemediationTarget {
  kind: RemediationKind;
  /**
   * `context.repo` with any `#branch` suffix stripped — empty when the
   * caller supplied no repo hint. When non-empty it MUST equal the
   * integration's configured `owner/repo`; the route rejects mismatches
   * with 422 because the issue/PR is always opened on the configured
   * repository (the hint never redirects it).
   */
  repo: string;
  /** Source branch, only set when `kind` is `pull_request`. */
  head?: string;
}

/**
 * Decides issue vs pull request. A pull request is only attempted when
 * the proposal is clean (`status === 'ok'`) AND the caller explicitly
 * supplied a source branch via a `owner/repo#branch` suffix on
 * `context.repo`; everything else defaults to an issue. Pure — the
 * unit tests pin both directions.
 */
export function selectRemediationTarget(
  proposalStatus: RemediationProposal['status'],
  repoHint?: string,
): RemediationTarget {
  const hint = repoHint ?? '';
  const sep = hint.indexOf('#');
  const repo = sep === -1 ? hint : hint.slice(0, sep);
  const head = sep === -1 ? '' : hint.slice(sep + 1);
  if (proposalStatus === 'ok' && head.length > 0) {
    return { kind: 'pull_request', repo, head };
  }
  return { kind: 'issue', repo };
}

/** No interpolated value may carry a backtick — one would end its code span. */
function codeSpan(s: string): string {
  return s.replace(/`/g, '');
}

/**
 * Deterministic markdown body for the issue/PR — same proposal in,
 * same text out. No LLM.
 */
export function renderRemediationBody(
  proposal: RemediationProposal,
  context?: RemediationContext,
): string {
  const lines: string[] = [
    '## Remediation proposal',
    '',
    `- **Package**: \`${codeSpan(proposal.package.name)}\` (${proposal.package.ecosystem})`,
    `- **Update**: \`${codeSpan(proposal.from)}\` -> \`${codeSpan(proposal.to)}\``,
    `- **Bump**: \`${proposal.bump}\``,
    `- **Risk**: \`${proposal.risk}\``,
    `- **Resolves**: ${
      proposal.resolves.length > 0
        ? proposal.resolves.map((r) => `\`${codeSpan(r)}\``).join(', ')
        : 'n/a'
    }`,
    '',
    '### Manifest change',
    '',
    // Four backticks: the schema already rejects ``` in `manifestHint`, but
    // even a leaked one cannot terminate a four-backtick fence.
    '````',
    proposal.manifestHint,
    '````',
  ];
  const contextLines: string[] = [];
  if (context?.findingId) contextLines.push(`- **Finding**: \`${codeSpan(context.findingId)}\``);
  if (context?.cveId) contextLines.push(`- **CVE**: \`${codeSpan(context.cveId)}\``);
  if (context?.assetId) contextLines.push(`- **Asset**: \`${codeSpan(context.assetId)}\``);
  if (context?.repo) contextLines.push(`- **Repo**: \`${codeSpan(context.repo)}\``);
  if (contextLines.length > 0) {
    lines.push('', '### Context', ...contextLines);
  }
  return lines.join('\n');
}

function remediationTitle(proposal: RemediationProposal): string {
  return `[remediation] ${proposal.package.name}: ${proposal.from} -> ${proposal.to}`;
}

/**
 * Resolves `config.token`/`config.pat`, decrypting with the
 * `AICC_CREDENTIAL_KEYS` keyring when one is configured and passing
 * plaintext through otherwise (same tolerance as the kubernetes-service
 * credential path).
 */
function resolveToken(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || raw.trim() === '') return undefined;
  const keys = process.env.AICC_CREDENTIAL_KEYS;
  if (!keys) return raw;
  try {
    return decryptSecret(parseKeyring(keys), raw, { allowPlaintext: true });
  } catch {
    // A crypto misconfiguration must surface as a clean 422, never as a 500
    // reflecting internal error text.
    throw new AppError('VALIDATION_ERROR', 'integration credential could not be decrypted', {
      statusCode: 422,
    });
  }
}

export const buildIntegrationRoutes: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, integrations, providers, syncs, bus } = opts;

  server.get('/v1/providers', async () => ({
    items: providers.list().map((p) => ({ id: p.id, name: p.name })),
  }));

  server.get('/v1/integrations', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const items = await integrations.list(tenantId);
    return { items: items.map(redactIntegration), total: items.length };
  });

  server.post('/v1/integrations', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const body = CreateIntegrationSchema.parse(req.body);
    if (!providers.get(body.provider)) {
      reply.code(400);
      return { code: 'VALIDATION_ERROR', message: `unknown provider: ${body.provider}` };
    }
    const integration = await integrations.create({ ...body, tenantId });
    return reply.code(201).send({ integration: redactIntegration(integration) });
  });

  server.get<{ Params: { id: string } }>('/v1/integrations/:id', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const i = await integrations.findById(req.params.id, tenantId);
    if (!i) throw new NotFoundError('Integration', req.params.id);
    return { integration: redactIntegration(i) };
  });

  server.patch<{ Params: { id: string } }>('/v1/integrations/:id/enabled', async (req) => {
    const tenantId = requireTenant(req.tenantId);
    const body = z.object({ enabled: z.boolean() }).parse(req.body);
    const updated = await integrations.setEnabled(req.params.id, tenantId, body.enabled);
    if (!updated) throw new NotFoundError('Integration', req.params.id);
    return { integration: redactIntegration(updated) };
  });

  server.delete<{ Params: { id: string } }>('/v1/integrations/:id', async (req, reply) => {
    const tenantId = requireTenant(req.tenantId);
    const ok = await integrations.remove(req.params.id, tenantId);
    if (!ok) throw new NotFoundError('Integration', req.params.id);
    reply.code(204).send();
  });

  server.post<{ Params: { integrationId: string } }>(
    '/v1/integrations/:integrationId/remediation',
    { preHandler: requirePlatformAdmin },
    async (req) => {
      const tenantId = requireTenant(req.tenantId);
      // safeParse → 400: a bare ZodError has no statusCode and would surface
      // as a 500 instead of the 4xx a bad request deserves.
      const parsed = RemediationRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        throw new ValidationError(
          `invalid remediation request: ${parsed.error.issues
            .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
            .join('; ')}`,
        );
      }
      const input = parsed.data;
      const integration = await integrations.findById(req.params.integrationId, tenantId);
      // Missing, foreign-tenant, and disabled integrations are all 404.
      if (!integration || !integration.enabled) {
        throw new NotFoundError('Integration', req.params.integrationId);
      }
      if (integration.provider !== 'github') {
        throw new AppError('CONFLICT', 'remediation apply requires a github integration');
      }
      const owner = integration.config.owner;
      const repo = integration.config.repo;
      if (typeof owner !== 'string' || owner === '' || typeof repo !== 'string' || repo === '') {
        throw new AppError(
          'VALIDATION_ERROR',
          'github integration config requires "owner" and "repo"',
          { statusCode: 422 },
        );
      }
      const configuredRepo = `${owner}/${repo}`;
      const target = selectRemediationTarget(input.proposal.status, input.context?.repo);
      // The GitHub client below always operates on
      // `integration.config.owner/repo`, so a `context.repo` naming any
      // other repository would be silently ignored — the caller would ask
      // for a PR on one repo and get an issue/PR on another. Reject the
      // mismatch up front instead.
      if (target.repo !== '' && target.repo !== configuredRepo) {
        throw new AppError(
          'VALIDATION_ERROR',
          `context.repo "${target.repo}" must match the integration's configured repository "${configuredRepo}"`,
          { statusCode: 422 },
        );
      }
      const rawToken = [integration.config.token, integration.config.pat].find(
        (v): v is string => typeof v === 'string' && v.trim() !== '',
      );
      const token = resolveToken(rawToken);
      if (!token) {
        throw new AppError(
          'VALIDATION_ERROR',
          'github integration config requires a token ("token" or "pat")',
          { statusCode: 422 },
        );
      }

      const title = remediationTitle(input.proposal);
      const body = renderRemediationBody(input.proposal, input.context);

      if (input.dryRun) {
        return {
          opened: false,
          dryRun: true,
          kind: target.kind,
          message: `dry run: would open a ${target.kind} on ${owner}/${repo}`,
        };
      }

      const client = new GithubClient({ token, owner, repo, baseUrl: process.env.GITHUB_API_URL });
      let ref: GithubRef;
      try {
        ref =
          target.kind === 'pull_request'
            ? await client.createPullRequest({ title, body, head: target.head! })
            : await client.createIssue({ title, body });
      } catch (err) {
        // Never leak GitHub's response body to the caller — log the
        // status and return a generic upstream failure.
        logger.warn(
          {
            status: err instanceof GithubApiError ? err.status : undefined,
            // Percent-escape exactly like GithubClient does — raw config
            // strings with newlines would forge structured log lines.
            url: `${process.env.GITHUB_API_URL ?? 'https://api.github.com'}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
          },
          'github remediation request failed',
        );
        await recordRemediationSync(syncs, bus, {
          tenantId,
          integrationId: integration.id,
          status: 'failed',
          metadata: {
            kind: target.kind,
            package: input.proposal.package,
            from: input.proposal.from,
            to: input.proposal.to,
            context: input.context ?? {},
          },
        });
        throw new AppError('UPSTREAM_FAILURE', `failed to open ${target.kind} on GitHub`, {
          statusCode: 502,
        });
      }

      await recordRemediationSync(syncs, bus, {
        tenantId,
        integrationId: integration.id,
        status: 'succeeded',
        metadata: {
          kind: target.kind,
          url: ref.url,
          number: ref.number,
          package: input.proposal.package,
          from: input.proposal.from,
          to: input.proposal.to,
          context: input.context ?? {},
        },
      });

      return {
        opened: true,
        dryRun: false,
        kind: target.kind,
        url: ref.url,
        number: ref.number,
        message: `opened ${target.kind} #${ref.number}`,
      };
    },
  );

  logger.debug('integration-service integration routes registered');
};

async function recordRemediationSync(
  syncs: SyncRepository,
  bus: EventBus,
  args: {
    tenantId: UUID;
    integrationId: UUID;
    status: 'succeeded' | 'failed';
    metadata: Record<string, unknown>;
  },
): Promise<void> {
  const sync = await syncs.create({
    tenantId: args.tenantId,
    integrationId: args.integrationId,
    kind: 'github.remediation',
    status: args.status,
    metadata: args.metadata,
  });
  await syncs.finish(sync.id, args.status);
  // Same shape as GithubProvider.handleEvent's sync-completed publish.
  await bus.publish({
    type: EventTypes.INTEGRATION_SYNC_COMPLETED,
    version: 1,
    source: 'integration-service',
    tenantId: args.tenantId,
    severity: 'info',
    data: {
      provider: 'github',
      eventType: 'remediation.apply',
      integrationId: args.integrationId,
    },
  });
}
