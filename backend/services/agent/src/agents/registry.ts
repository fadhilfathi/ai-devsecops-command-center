/**
 * Agent registry — Sprint 1 ships two skeleton agents:
 *
 *   - triage-agent:   reads scan findings, decides severity & routing
 *   - remediation-agent: proposes fixes and creates incidents
 *
 * The contract for how agents exchange messages is defined by the
 * PlatformArchitect in `docs/architecture/event-bus.md`. In Sprint 1
 * agents run synchronously inside the same process; Sprint 2 will
 * dispatch them to isolated workers.
 */
import type { EventBus, Logger } from '@aicc/shared';
import { EventTypes } from '@aicc/shared';
import type { TaskQueue, AgentTask } from '../services/task-queue.js';
import { triage } from './triage.js';
import { proposeRemediation, applyRemediation } from './remediation.js';

export interface AgentContext {
  bus: EventBus;
  queue: TaskQueue;
  logger: Logger;
}

export interface Agent {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  canHandle(kind: string): boolean;
  run(task: AgentTask, ctx: AgentContext): Promise<Record<string, unknown>>;
}

export interface AgentRegistry {
  agents(): Agent[];
  dispatch(task: AgentTask, ctx: AgentContext): Promise<AgentTask>;
}

class TriageAgent implements Agent {
  readonly id = 'triage-agent';
  readonly name = 'Triage Agent';
  readonly description =
    'Classifies scan findings and routes them to incidents or compliance checks.';
  canHandle(kind: string): boolean {
    return kind === 'triage.findings';
  }
  async run(task: AgentTask, ctx: AgentContext): Promise<Record<string, unknown>> {
    ctx.logger.info({ taskId: task.id, kind: task.kind }, 'triage agent running');
    const result = await triage(task.input, ctx.logger);
    return { ...result };
  }
}

class RemediationAgent implements Agent {
  readonly id = 'remediation-agent';
  readonly name = 'Remediation Agent';
  readonly description =
    'Proposes code or config fixes and can open PRs via the integration service.';
  canHandle(kind: string): boolean {
    return kind === 'remediation.propose' || kind === 'remediation.apply';
  }
  async run(task: AgentTask, ctx: AgentContext): Promise<Record<string, unknown>> {
    ctx.logger.info({ taskId: task.id, kind: task.kind }, 'remediation agent running');
    if (task.kind === 'remediation.apply') {
      return { ...applyRemediation() };
    }
    return { ...proposeRemediation(task.input) };
  }
}

class ComplianceMappingAgent implements Agent {
  readonly id = 'compliance-mapping-agent';
  readonly name = 'Compliance Mapping Agent';
  readonly description = 'Maps scan findings & control evidence to CIS/NIST controls.';
  canHandle(kind: string): boolean {
    return kind === 'compliance.map';
  }
  async run(task: AgentTask, ctx: AgentContext): Promise<Record<string, unknown>> {
    ctx.logger.info({ taskId: task.id, kind: task.kind }, 'compliance mapping agent running');
    return {
      mappings: [],
      mappedAt: new Date().toISOString(),
    };
  }
}

export function buildAgentRegistry(ctx: AgentContext): AgentRegistry {
  const agents: Agent[] = [new TriageAgent(), new RemediationAgent(), new ComplianceMappingAgent()];

  return {
    agents() {
      return agents;
    },
    async dispatch(task, dispatchCtx) {
      const agent = agents.find((a) => a.canHandle(task.kind));
      if (!agent) {
        const failed = await ctx.queue.fail(task.id, `no agent registered for kind=${task.kind}`);
        await ctx.bus.publish({
          type: EventTypes.AGENT_TASK_COMPLETED,
          version: 1,
          source: 'agent-service',
          tenantId: task.tenantId,
          severity: 'info',
          data: { taskId: task.id, status: 'failed', reason: 'no_agent' },
        });
        return failed!;
      }
      try {
        const result = await agent.run(task, dispatchCtx);
        const done = await ctx.queue.complete(task.id, result);
        await ctx.bus.publish({
          type: EventTypes.AGENT_TASK_COMPLETED,
          version: 1,
          source: 'agent-service',
          tenantId: task.tenantId,
          severity: 'info',
          data: { taskId: task.id, agentId: agent.id, status: 'completed' },
        });
        return done!;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const failed = await ctx.queue.fail(task.id, message);
        await ctx.bus.publish({
          type: EventTypes.AGENT_TASK_COMPLETED,
          version: 1,
          source: 'agent-service',
          tenantId: task.tenantId,
          severity: 'high',
          data: { taskId: task.id, agentId: agent.id, status: 'failed', error: message },
        });
        return failed!;
      }
    },
  };
}
