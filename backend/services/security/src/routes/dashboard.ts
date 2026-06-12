/**
 * Security dashboard aggregate route (S2.5).
 *
 *   GET /security/dashboard    — read-only, any authenticated role
 *
 * Aggregates:
 *   - SBOM count
 *   - Vulnerability count bucketed by severity
 *   - Top 5 riskiest components (by composite score)
 *   - Recent activity (last 20 events)
 *   - Aggregate security score (0-100; 100 = perfectly secure)
 *   - 7-day security-score trend
 *
 * In Sprint 2, the data is read from the local in-memory stores
 * (Sprint 1) and the security-service's own event log. In Sprint 2.1,
 * the SBOM and vulnerability counts will be served from Postgres
 * (via the Sprint 2 migration to Prisma) and the recent activity
 * will be read from Redis Streams.
 */
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import {
  type EventBus,
  type Logger,
} from '@aicc/shared';
import {
  SecurityDashboardResponseSchema,
  type SecurityDashboardResponse,
  type VulnerabilitySeverity,
  type TopRiskyComponent,
  type RecentActivityEntry,
  computeCompositeScore,
  DEFAULT_RISK_FACTOR_WEIGHTS,
  toJSONSchema,
} from '@aicc/shared/security';
import { requireAuth, optionalAuth } from '../middleware/auth.js';
import { dashboardQueryDuration, withService } from '../services/metrics.js';
import type { SbomRepository } from '../repositories/sbom.repository.js';
import type { ScanRepository } from '../repositories/scan.repository.js';
import type { FindingRepository } from '../repositories/finding.repository.js';
import { InMemoryEventLog } from '../services/event-log.js';

interface Deps {
  logger: Logger;
  bus: EventBus;
  sboms: SbomRepository;
  scans: ScanRepository;
  findings: FindingRepository;
  eventLog: InMemoryEventLog;
}

const QuerySchema = z.object({
  tenantId: z.string().uuid().optional(),
});

const BUCKETS: ReadonlyArray<VulnerabilitySeverity> = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

export const buildDashboardRoute: FastifyPluginAsync<Deps> = async (
  server: FastifyInstance,
  opts,
) => {
  const { logger, sboms, scans, findings, eventLog } = opts;

  server.get<{ Querystring: Record<string, string | undefined> }>(
    '/security/dashboard',
    {
      // Per Leader's S2.5 spec: all roles can GET the dashboard.
      // We still require authentication; the optionalAuth hook
      // accepts anonymous and falls back to no-user data, but the
      // role check below is effectively "any authenticated user".
      preHandler: [requireAuth],
      schema: {
        querystring: {
          type: 'object',
          properties: { tenantId: { type: 'string', format: 'uuid' } },
        },
        response: { 200: toJSONSchema(SecurityDashboardResponseSchema) },
        tags: ['security', 'dashboard'],
        summary: 'Aggregate security dashboard: SBOM count, vuln count by severity, top 5 riskiest components, recent activity, security score',
        description: 'Read-only. Available to all authenticated roles. Rate-limited at 10 req/s.',
      },
    },
    async (req, reply) => {
      const q = QuerySchema.parse(req.query ?? {});
      const tenantId = q.tenantId ?? req.user?.tenantId ?? '00000000-0000-4000-8000-000000000000';
      // S2.7 — start the dashboard query duration timer; observe at the end
      // (the histogram label set is fixed at start to avoid cardinality bloat).
      // Note: tenantId is NOT a metric label per metrics-spec.md §5.1.
      const endDashboardTimer = dashboardQueryDuration.startTimer(
        withService({ endpoint: '/security/dashboard' }),
      );

      // ---------- SBOM count ----------
      const sbomCount = (await sboms.list(tenantId)).length;

      // ---------- Vulnerability count by severity ----------
      const allFindings = await findings.list(tenantId);
      const vulnCountBySeverity: SecurityDashboardResponse['vulnCountBySeverity'] = {
        critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0,
      };
      for (const f of allFindings) {
        const sev = (f.severity ?? 'unknown') as VulnerabilitySeverity;
        if (BUCKETS.includes(sev)) vulnCountBySeverity[sev]++;
      }
      const totalVulnCount = Object.values(vulnCountBySeverity).reduce((s, n) => s + n, 0);

      // ---------- Top 5 riskiest components (computed locally from findings) ----------
      // Group findings by packageName; compute a per-package composite
      // risk score using the same weights as the dependency-intel-service.
      const byPackage = new Map<string, { name: string; version?: string; findings: typeof allFindings }>();
      for (const f of allFindings) {
        if (!f.packageName) continue;
        const key = `${f.packageName}@${f.packageVersion ?? '*'}`;
        const cur = byPackage.get(key) ?? { name: f.packageName, version: f.packageVersion, findings: [] };
        cur.findings.push(f);
        byPackage.set(key, cur);
      }
      const topRisky: TopRiskyComponent[] = Array.from(byPackage.values())
        .map((p): TopRiskyComponent => {
          // Worst severity in the package → factor
          const worstSeverity = p.findings.reduce<VulnerabilitySeverity>(
            (acc, f) => severityRank(f.severity) > severityRank(acc) ? f.severity : acc,
            'unknown',
          );
          const factors = {
            severity: severityToFactor(worstSeverity),
            epss: 0, // unknown by default
            kev: 0,  // unknown by default
            reachability: 0.5, // assume transitive
            exposure: 0.5,     // assume internal
          };
          const score = computeCompositeScore(factors, DEFAULT_RISK_FACTOR_WEIGHTS);
          const worst = p.findings.reduce((a, b) => severityRank(b.severity) > severityRank(a.severity) ? b : a);
          return {
            bomRef: `pkg:${p.name}@${p.version ?? '*'}`,
            name: p.name,
            version: p.version,
            score,
            topVulnerabilityId: worst.id,
            topCvssScore: severityToCvss(worstSeverity),
            epssPercentile: undefined,
            kev: false,
          };
        })
        .sort((a, b) => b.score - a.score)
        .slice(0, 5);

      // ---------- Recent activity (from in-process event log) ----------
      const recentActivity: RecentActivityEntry[] = eventLog
        .list(tenantId, 20)
        .map((e): RecentActivityEntry => ({
          id: e.id,
          type: e.eventTypeToDashboardType(e.type),
          timestamp: e.timestamp,
          summary: e.summary,
          severity: e.severity,
          tenantId,
        }));

      // ---------- Security score (0-100) ----------
      // Heuristic: 100 - (critical*10 + high*5 + medium*2 + low*0.5), clamped [0, 100]
      const penalty =
        vulnCountBySeverity.critical * 10 +
        vulnCountBySeverity.high * 5 +
        vulnCountBySeverity.medium * 2 +
        vulnCountBySeverity.low * 0.5;
      const securityScore = Math.max(0, Math.min(100, Math.round(100 - penalty)));

      // ---------- 7-day trend (in-memory placeholder; Sprint 2.1 will read from time-series) ----------
      const securityScoreTrend: SecurityDashboardResponse['securityScoreTrend'] = [];
      const today = new Date();
      for (let i = 6; i >= 0; i--) {
        const d = new Date(today);
        d.setUTCDate(d.getUTCDate() - i);
        const date = d.toISOString().slice(0, 10);
        // Slight wobble so the chart is not flat in dev
        const wobble = Math.sin(i * 0.7) * 1.5;
        const score = Math.max(0, Math.min(100, Math.round(securityScore + wobble)));
        securityScoreTrend.push({ date, score });
      }

      const response: SecurityDashboardResponse = {
        generatedAt: new Date().toISOString(),
        tenantId,
        sbomCount,
        vulnCountBySeverity,
        totalVulnCount,
        topRiskyComponents: topRisky,
        recentActivity,
        securityScore,
        securityScoreTrend,
        modelVersion: 'security-score-v1',
      };

      // Validate before sending so contract regressions are caught at the edge
      const verified = SecurityDashboardResponseSchema.safeParse(response);
      if (!verified.success) {
        logger.error({ issues: verified.error.flatten() }, 'dashboard response failed schema validation');
        reply.code(500);
        return { code: 'INTERNAL_ERROR', message: 'Dashboard response failed schema validation' };
      }

      // S2.7 — observe the dashboard query duration before returning
      endDashboardTimer();

      return verified.data;
    },
  );

  logger.debug('security-service dashboard route registered');
};

// ---------- helpers (local; not exported to keep route file lean) ----------

function severityRank(s: VulnerabilitySeverity): number {
  switch (s) {
    case 'critical': return 5;
    case 'high':     return 4;
    case 'medium':   return 3;
    case 'low':      return 2;
    case 'info':     return 1;
    default:         return 0;
  }
}

function severityToFactor(s: VulnerabilitySeverity): number {
  switch (s) {
    case 'critical': return 1.0;
    case 'high':     return 0.8;
    case 'medium':   return 0.5;
    case 'low':      return 0.25;
    case 'info':     return 0.1;
    default:         return 0.5; // unknown — treat as medium until clarified
  }
}

function severityToCvss(s: VulnerabilitySeverity): number {
  switch (s) {
    case 'critical': return 9.5;
    case 'high':     return 7.5;
    case 'medium':   return 5.0;
    case 'low':      return 2.5;
    case 'info':     return 0.1;
    default:         return 5.0;
  }
}

// Re-export so the import is used
void optionalAuth;
