/**
 * GitOps wire-format projection for vulnerabilities.
 *
 * Per the O-3.5 contract lock (2026-06-12, signed off by GitOpsManager):
 *   - Internal `Vulnerability` (rich, camelCase, per-(CVE, package))
 *   - → GitOps wire format `VulnerabilityGitOpsRecord` (flat, snake_case,
 *     matches the `security/README.md` NDJSON record schema)
 *
 * The security-service :4003 is the **projection boundary** (chosen by
 * GitOpsManager because: cohesive with the 5 S2.5 REST endpoints + event-log
 * subscriber, and the Python agents keep their rich per-CVE model for
 * downstream consumers that need it).
 *
 * The 3-condition `autoActionable` gate is set HERE based on:
 *   1. KEV: `kev === true` (CISA Known Exploited)
 *   2. Fix available: `fixedIn.length > 0` for the affected package
 *   3. In-graph: caller passes `inGraph: boolean` from the dependency-intel
 *      service's graph lookup. Sprint 2 defaults to `false`; Sprint 2.1
 *      plumbs the actual graph check via `req.app.dependencyGraph`.
 *
 * Field renames (camelCase → snake_case) and the `ghsa` → `github-advisory`
 * source enum mapping are the only "magic" here; everything else is direct
 * pass-through from the rich schema.
 */
import type { Vulnerability, VulnerabilityGitOpsRecord } from '@aicc/shared/security';
import type { Logger } from 'pino';

/**
 * Project a rich `Vulnerability` to the GitOps wire format.
 *
 * The `Vulnerability` schema (v0.2.0) is already per-(CVE, package), so no
 * explosion on `affected[]` is needed. The function takes a single
 * `Vulnerability` and returns a single `VulnerabilityGitOpsRecord`.
 *
 * @param vuln  Rich per-(CVE, package) vulnerability record
 * @param opts.inGraph     Whether the affected package is in the dependency graph
 *                         (Sprint 2: default `false`; Sprint 2.1: plumbed from
 *                         dependency-intel :4009 lookup)
 * @param opts.tenantId    Tenant id (stamped at emit; optional in the wire format)
 * @param opts.now         Override `detected_at` (defaults to `vuln.detectedAt ?? new Date()`)
 * @param opts.logger      Optional logger for the `autoActionable` decision
 * @returns The GitOps wire-format record
 */
export function toGitOpsRecord(
  vuln: Vulnerability,
  opts: {
    inGraph: boolean;
    tenantId?: string;
    now?: Date;
    logger?: Logger;
  },
): VulnerabilityGitOpsRecord {
  const now = opts.now ?? new Date();
  const affected = vuln.affected[0]; // v0.2.0: per-(CVE, package), so affected[0] is THE package
  if (!affected) {
    throw new Error(
      `toGitOpsRecord: vulnerability ${vuln.id} has no affected[] entries; cannot project per-package wire format`,
    );
  }

  // 3-condition autoActionable gate.
  const hasKev = vuln.kev === true;
  const hasFix = affected.fixedIn.length > 0;
  const isInGraph = opts.inGraph;
  const autoActionable = hasKev && hasFix && isInGraph;
  if (opts.logger && autoActionable) {
    opts.logger.info(
      { vulnId: vuln.id, package: affected.package.name, kev: hasKev, fix: hasFix, inGraph: isInGraph },
      'auto_actionable=true (KEV + fix-available + in-graph)',
    );
  }

  // `ghsa` (internal) → `github-advisory` (wire). All other source values pass through.
  const wireSource: VulnerabilityGitOpsRecord['source'] =
    vuln.source === 'ghsa' ? 'github-advisory' : (vuln.source as VulnerabilityGitOpsRecord['source']);

  // CVSS v3: project the object to a flat number.
  const cvssV3 = vuln.cvssV3?.baseScore ?? null;

  // Summary: prefer explicit `summary` field; fall back to first description value.
  const summary = vuln.summary ?? vuln.descriptions[0]?.value ?? '';

  // References: project from object[] to URL string[].
  const references = vuln.references.map((r) => r.url);

  // vulnerable_range: prefer first `vulnerableRanges[].expression`; fall back to `''` if missing.
  const vulnerableRange = affected.vulnerableRanges[0]?.expression ?? '';

  return {
    id: vuln.id,
    source: wireSource,
    severity: vuln.severity,
    cvss_v3: cvssV3,
    package: affected.package.name,
    ecosystem: affected.package.ecosystem,
    introduced_in: affected.introducedIn ?? null,
    fixed_in: affected.fixedIn,
    vulnerable_range: vulnerableRange,
    summary,
    references,
    detected_at: vuln.detectedAt ?? now.toISOString(),
    git_sha: vuln.gitSha,
    auto_actionable: autoActionable,
    kind: vuln.kind,
    tenant_id: opts.tenantId,
  };
}

/**
 * Project an array of `Vulnerability` records to an array of GitOps wire records.
 * Thin wrapper over `toGitOpsRecord` for ergonomic call-site use.
 */
export function toGitOpsRecords(
  vulns: readonly Vulnerability[],
  opts: {
    inGraphLookup: (pkgName: string, ecosystem: string) => boolean;
    tenantId?: string;
    now?: Date;
    logger?: Logger;
  },
): VulnerabilityGitOpsRecord[] {
  return vulns.map((v) => {
    const affected = v.affected[0];
    return toGitOpsRecord(v, {
      inGraph: affected ? opts.inGraphLookup(affected.package.name, affected.package.ecosystem) : false,
      tenantId: opts.tenantId,
      now: opts.now,
      logger: opts.logger,
    });
  });
}
