/**
 * Correlation listener — feeds every event on the bus through
 * the correlation engine and persists the resulting chains.
 *
 * The listener subscribes to the canonical EventTypes.* topics
 * (security, sbom, deployment, k8s) and to a few auxiliary
 * topics needed for Sprint 4. The handler is intentionally
 * best-effort: a misbehaving event must never break the bus.
 */
import {
  EventTypes,
  type EventBus,
  type EventEnvelope,
  type Logger,
  type UUID,
} from '@aicc/shared';
import { buildCorrelationEngine, type CorrelationEvent } from '../correlation/correlation-engine.js';
import type { ChainRepository } from '../correlation/chain.repository.js';

interface Deps {
  bus: EventBus;
  chains: ChainRepository;
  logger: Logger;
}

const SUBSCRIBE_TOPICS: string[] = [
  EventTypes.VULNERABILITY_DETECTED,
  EventTypes.SCAN_COMPLETED,
  EventTypes.INCIDENT_CREATED,
  EventTypes.INCIDENT_RESOLVED,
  // Auxiliary topics (raw event types the integration
  // service / k8s services / cicd services publish).
  'sbom.finding',
  'sbom.vulnerability',
  'cicd.build.failed',
  'build.failed',
  'pipeline.failed',
  'cicd.deployment.blocked',
  'deployment.blocked',
  'policy.violation',
  'cicd.deployment.manual_override',
  'deployment.override',
  'k8s.event',
  'k8s.pod.warning',
  'k8s.deployment.failed',
  'infrastructure.finding',
  'cost.finding',
  'deployment.event',
  'deployment.succeeded',
  'deployment.started',
  'runtime.risk',
  'health.recommendation',
];

export async function buildCorrelationListener(deps: Deps): Promise<{ engine: ReturnType<typeof buildCorrelationEngine>; buffer: CorrelationEvent[]; }> {
  const engine = buildCorrelationEngine();
  const buffer: CorrelationEvent[] = [];
  const flush = async () => {
    if (buffer.length === 0) return;
    const drained = buffer.splice(0, buffer.length);
    try {
      const { chains, edges } = engine.correlate(drained);
      for (let i = 0; i < chains.length; i++) {
        await deps.chains.add(chains[i]!, edges);
      }
      if (chains.length > 0) {
        deps.logger.info({ chains: chains.length, events: drained.length }, 'correlation: built chains');
      }
    } catch (err) {
      deps.logger.error({ err, count: drained.length }, 'correlation: failed to build chains');
    }
  };

  for (const topic of SUBSCRIBE_TOPICS) {
    await deps.bus.subscribe(topic, async (event: EventEnvelope) => {
      try {
        const norm = engine.normalise(event);
        if (!norm) return;
        buffer.push(norm);
        if (buffer.length >= 16) {
          await flush();
        } else {
          // Also flush on a small delay so chains are visible quickly.
          setTimeout(() => { void flush(); }, 250).unref();
        }
      } catch (err) {
        deps.logger.error({ err, topic }, 'correlation: failed to normalise event');
      }
      void (null as unknown as UUID);
    });
  }
  return { engine, buffer };
}
