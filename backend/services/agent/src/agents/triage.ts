/**
 * Triage scoring — deterministic heuristic (always on) with an optional
 * LLM refinement pass.
 *
 * The heuristic is the default and the platform's only requirement: it
 * needs no API key and no network access (CLAUDE.md's zero-cost rule).
 * The LLM pass is opt-in via env vars and can only nudge the heuristic's
 * priority by one level — any anomaly (disabled, no key, timeout,
 * non-2xx, bad JSON, schema mismatch, out-of-band clamp) falls back to
 * the heuristic result untouched. See docs/adr/0020 for the rationale.
 */
import type { Logger } from '@aicc/shared';
import { z } from 'zod';

export const FindingSchema = z.object({
  id: z.string().max(128).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']),
  cveId: z.string().max(32).optional(),
  kev: z.boolean().optional(),
  epss: z.number().min(0).max(1).optional(),
  cvss: z.number().min(0).max(10).optional(),
  fixAvailable: z.boolean().optional(),
  assetCriticality: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  exposure: z.enum(['internet', 'internal']).optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const TriageInputSchema = z.object({
  findings: z.array(FindingSchema).default([]),
});

export type Decision = 'open_incident' | 'create_ticket' | 'log_only';
export type Priority = 'P1' | 'P2' | 'P3' | 'P4';
export type Engine = 'heuristic' | 'llm';

export interface PerFindingScore {
  id?: string;
  score: number;
  priority: Priority;
}

export interface TriageResult {
  decision: Decision;
  priority: Priority;
  rationale: string[];
  perFinding: PerFindingScore[];
  counts: { total: number; critical: number; high: number };
  engine: Engine;
  triagedAt: string;
}

const TriageResultSchema = z.object({
  decision: z.enum(['open_incident', 'create_ticket', 'log_only']),
  priority: z.enum(['P1', 'P2', 'P3', 'P4']),
  rationale: z.array(z.string()).min(1),
});
type LlmTriageReply = z.infer<typeof TriageResultSchema>;

const PRIORITY_ORDER: Priority[] = ['P1', 'P2', 'P3', 'P4'];
const SEVERITY_BASE: Record<Finding['severity'], number> = {
  critical: 80,
  high: 60,
  medium: 35,
  low: 15,
  informational: 5,
};

/**
 * Score a single finding. Pure, deterministic, and explainable — every
 * contributing factor is returned as a rationale string.
 *
 * Base score by severity, then:
 *   + 25 known-exploited (CISA KEV)
 *   + 15 high exploitation probability (EPSS >= 0.5)
 *   + 10 internet-exposed asset
 *   + 10 critical-criticality asset, +5 high-criticality asset
 *   - 5  a fix is already available (lowers urgency slightly; it does not
 *        change whether we open an incident, only how loudly we shout)
 */
function scoreFinding(f: Finding): { score: number; rationale: string[] } {
  const rationale: string[] = [];
  let score = SEVERITY_BASE[f.severity];
  rationale.push(`base ${score} for ${f.severity} severity`);

  if (f.kev) {
    score += 25;
    rationale.push('+25 known exploited (CISA KEV)');
  }
  if (f.epss !== undefined && f.epss >= 0.5) {
    score += 15;
    rationale.push(`+15 high exploitation probability (EPSS ${f.epss})`);
  }
  if (f.exposure === 'internet') {
    score += 10;
    rationale.push('+10 internet-exposed asset');
  }
  if (f.assetCriticality === 'critical') {
    score += 10;
    rationale.push('+10 critical-criticality asset');
  } else if (f.assetCriticality === 'high') {
    score += 5;
    rationale.push('+5 high-criticality asset');
  }
  if (f.fixAvailable === false) {
    score -= 5;
    rationale.push('-5 no fix available yet');
  }

  const label = f.id ?? f.cveId ?? 'finding';
  return { score, rationale: rationale.map((r) => `${label}: ${r}`) };
}

function priorityForScore(score: number): Priority {
  if (score >= 80) return 'P1';
  if (score >= 60) return 'P2';
  if (score >= 35) return 'P3';
  return 'P4';
}

function decisionForPriority(priority: Priority): Decision {
  if (priority === 'P1' || priority === 'P2') return 'open_incident';
  if (priority === 'P3') return 'create_ticket';
  return 'log_only';
}

/** Deterministic, zero-cost triage. Always available, no network calls. */
export function heuristicTriage(input: unknown): TriageResult {
  const { findings } = TriageInputSchema.parse(input);

  if (findings.length === 0) {
    return {
      decision: 'log_only',
      priority: 'P4',
      rationale: ['no findings supplied'],
      perFinding: [],
      counts: { total: 0, critical: 0, high: 0 },
      engine: 'heuristic',
      triagedAt: new Date().toISOString(),
    };
  }

  const rationale: string[] = [];
  const perFinding: PerFindingScore[] = [];
  let topScore = -Infinity;

  for (const f of findings) {
    const { score, rationale: findingRationale } = scoreFinding(f);
    rationale.push(...findingRationale);
    const priority = priorityForScore(score);
    perFinding.push({ id: f.id ?? f.cveId, score, priority });
    if (score > topScore) topScore = score;
  }

  const priority = priorityForScore(topScore);
  const decision = decisionForPriority(priority);
  rationale.push(`overall: highest score ${topScore} -> priority ${priority} -> ${decision}`);

  return {
    decision,
    priority,
    rationale,
    perFinding,
    counts: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
    },
    engine: 'heuristic',
    triagedAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Optional LLM refinement
// ---------------------------------------------------------------------------

export interface LlmTriageConfig {
  enabled: boolean;
  apiKey: string;
  baseUrl: string;
  model: string;
  timeoutMs: number;
}

export function loadLlmTriageConfig(env: NodeJS.ProcessEnv = process.env): LlmTriageConfig {
  return {
    enabled: env.AICC_AGENT_LLM_ENABLED === 'true',
    apiKey: env.AICC_AGENT_LLM_API_KEY ?? '',
    baseUrl: env.AICC_AGENT_LLM_BASE_URL ?? 'https://api.openai.com/v1',
    model: env.AICC_AGENT_LLM_MODEL ?? 'gpt-4o-mini',
    timeoutMs: Number(env.AICC_AGENT_LLM_TIMEOUT_MS ?? 10_000),
  };
}

const MAX_FINDINGS_TO_LLM = 50;

function clampWithinOneLevel(heuristic: Priority, proposed: Priority): boolean {
  const gap = Math.abs(PRIORITY_ORDER.indexOf(heuristic) - PRIORITY_ORDER.indexOf(proposed));
  return gap <= 1;
}

/**
 * Strip findings down to structured-only fields (no free text) before
 * they go anywhere near a prompt, and cap the count. This is the entire
 * prompt-injection surface: only these fields ever reach the LLM.
 */
const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

function sanitizeFindingsForPrompt(findings: Finding[]): Omit<Finding, 'id'>[] {
  // `id` is not needed for scoring and is free text, so it never reaches
  // the prompt; a cveId that is not a well-formed CVE identifier is dropped.
  return findings.slice(0, MAX_FINDINGS_TO_LLM).map((f) => ({
    severity: f.severity,
    cveId: f.cveId && CVE_ID.test(f.cveId) ? f.cveId : undefined,
    kev: f.kev,
    epss: f.epss,
    cvss: f.cvss,
    fixAvailable: f.fixAvailable,
    assetCriticality: f.assetCriticality,
    exposure: f.exposure,
  }));
}

const SYSTEM_PROMPT =
  'You are a security triage assistant. You are given a heuristic triage ' +
  'decision and a list of structured findings. You may refine the ' +
  'decision and priority, but only by at most one priority level in ' +
  'either direction from the heuristic result. Respond with a single ' +
  'JSON object: {"decision":"open_incident|create_ticket|log_only",' +
  '"priority":"P1|P2|P3|P4","rationale":["..."]}. No other text.';

/**
 * Optional LLM-assisted refinement of a heuristic triage result. Any
 * failure at any step returns `heuristic` unchanged with `engine:
 * 'heuristic'` — the LLM pass never blocks or breaks triage.
 */
export async function refineWithLlm(
  heuristic: TriageResult,
  findings: Finding[],
  config: LlmTriageConfig,
  logger: Logger,
): Promise<TriageResult> {
  if (!config.enabled || !config.apiKey) {
    return heuristic;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);
  try {
    const res = await fetch(`${config.baseUrl.replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        model: config.model,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          {
            role: 'user',
            content: JSON.stringify({
              heuristic: {
                decision: heuristic.decision,
                priority: heuristic.priority,
                counts: heuristic.counts,
              },
              findings: sanitizeFindingsForPrompt(findings),
            }),
          },
        ],
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      logger.warn({ status: res.status }, 'triage llm refinement failed: non-2xx response');
      return heuristic;
    }

    const body = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = body.choices?.[0]?.message?.content;
    if (typeof content !== 'string') {
      logger.warn('triage llm refinement failed: no message content');
      return heuristic;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      logger.warn('triage llm refinement failed: invalid JSON');
      return heuristic;
    }

    const result = TriageResultSchema.safeParse(parsed);
    if (!result.success) {
      logger.warn('triage llm refinement failed: response did not match schema');
      return heuristic;
    }
    const reply: LlmTriageReply = result.data;

    if (!clampWithinOneLevel(heuristic.priority, reply.priority)) {
      logger.warn(
        { heuristicPriority: heuristic.priority, proposedPriority: reply.priority },
        'triage llm refinement discarded: priority moved more than one level',
      );
      return heuristic;
    }

    // The decision always follows the clamped priority; the model cannot
    // choose a decision independently of it.
    return {
      ...heuristic,
      decision: decisionForPriority(reply.priority),
      priority: reply.priority,
      rationale: [...heuristic.rationale, ...reply.rationale],
      engine: 'llm',
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn({ error: message }, 'triage llm refinement failed: transport error or timeout');
    return heuristic;
  } finally {
    clearTimeout(timer);
  }
}

export async function triage(
  input: unknown,
  logger: Logger,
  env: NodeJS.ProcessEnv = process.env,
): Promise<TriageResult> {
  const heuristic = heuristicTriage(input);
  const config = loadLlmTriageConfig(env);
  if (!config.enabled) return heuristic;
  const { findings } = TriageInputSchema.parse(input);
  return refineWithLlm(heuristic, findings, config, logger);
}
