/**
 * Provider registry — Sprint 1 ships stubs for all 5 supported
 * providers. Each provider exposes:
 *   - id, name
 *   - verifyWebhookSignature(rawBody, headers) -> boolean
 *   - handleEvent(event)                       -> Promise<void>
 *
 * In Sprint 2 the GitHub provider will be wired to the GitHub App
 * defined by the SecurityArchitect, and the others will follow.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { EventTypes, type EventBus, type Logger } from '@aicc/shared';
import type { SyncRepository } from '../repositories/sync.repository.js';

export interface ProviderEvent {
  type: string;
  tenantId: string;
  integrationId: string;
  payload: Record<string, unknown>;
}

export interface Provider {
  readonly id: string;
  readonly name: string;
  verifyWebhookSignature(rawBody: Buffer, headers: Record<string, string | string[]>): boolean;
  handleEvent(event: ProviderEvent, ctx: ProviderContext): Promise<void>;
}

export interface ProviderContext {
  bus: EventBus;
  logger: Logger;
  syncs: SyncRepository;
}

export interface ProviderRegistry {
  list(): Provider[];
  get(id: string): Provider | undefined;
}

class GithubProvider implements Provider {
  readonly id = 'github';
  readonly name = 'GitHub';
  verifyWebhookSignature(rawBody: Buffer, headers: Record<string, string | string[]>): boolean {
    const secret = process.env.GITHUB_WEBHOOK_SECRET;
    const sig = headers['x-hub-signature-256'];
    if (!secret || !sig || Array.isArray(sig)) return false;
    const expected = 'sha256=' + createHmac('sha256', secret).update(rawBody).digest('hex');
    try {
      const a = Buffer.from(sig);
      const b = Buffer.from(expected);
      return a.length === b.length && timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }
  async handleEvent(event: ProviderEvent, ctx: ProviderContext): Promise<void> {
    // Sprint 1: publish a domain event; Sprint 2 will react per event type.
    const sync = await ctx.syncs.create({
      tenantId: event.tenantId as never,
      integrationId: event.integrationId as never,
      kind: `github.${event.type}`,
      status: 'succeeded',
      metadata: { payload: event.payload },
    });
    await ctx.syncs.finish(sync.id, 'succeeded');
    await ctx.bus.publish({
      type: EventTypes.INTEGRATION_SYNC_COMPLETED,
      version: 1,
      source: 'integration-service',
      tenantId: event.tenantId,
      severity: 'info',
      data: { provider: this.id, eventType: event.type, integrationId: event.integrationId },
    });
  }
}

class GitlabProvider implements Provider {
  readonly id = 'gitlab';
  readonly name = 'GitLab';
  verifyWebhookSignature(rawBody: Buffer, headers: Record<string, string | string[]>): boolean {
    const token = process.env.GITLAB_WEBHOOK_TOKEN;
    const got = headers['x-gitlab-token'];
    if (!token || !got || Array.isArray(got)) return false;
    return token === got;
  }
  async handleEvent(event: ProviderEvent, ctx: ProviderContext): Promise<void> {
    ctx.logger.debug({ event: event.type }, 'gitlab event received (no-op in sprint 1)');
  }
}

class BitbucketProvider implements Provider {
  readonly id = 'bitbucket';
  readonly name = 'Bitbucket';
  verifyWebhookSignature(_rawBody: Buffer, _headers: Record<string, string | string[]>): boolean {
    // Sprint 2: implement Bitbucket signature verification.
    return true;
  }
  async handleEvent(_event: ProviderEvent, _ctx: ProviderContext): Promise<void> {
    /* no-op */
  }
}

class JiraProvider implements Provider {
  readonly id = 'jira';
  readonly name = 'Jira';
  verifyWebhookSignature(_rawBody: Buffer, _headers: Record<string, string | string[]>): boolean {
    return true;
  }
  async handleEvent(_event: ProviderEvent, _ctx: ProviderContext): Promise<void> {
    /* no-op */
  }
}

class SlackProvider implements Provider {
  readonly id = 'slack';
  readonly name = 'Slack';
  verifyWebhookSignature(_rawBody: Buffer, headers: Record<string, string | string[]>): boolean {
    // Sprint 2: implement Slack signing secret verification.
    void headers;
    return true;
  }
  async handleEvent(_event: ProviderEvent, _ctx: ProviderContext): Promise<void> {
    /* no-op */
  }
}

export function buildProviderRegistry(_ctx: ProviderContext): ProviderRegistry {
  const providers: Provider[] = [
    new GithubProvider(),
    new GitlabProvider(),
    new BitbucketProvider(),
    new JiraProvider(),
    new SlackProvider(),
  ];
  return {
    list() {
      return providers;
    },
    get(id) {
      return providers.find((p) => p.id === id);
    },
  };
}
