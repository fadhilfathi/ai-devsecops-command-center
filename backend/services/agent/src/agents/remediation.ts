/**
 * Remediation proposals — deterministic dependency-bump suggestions.
 *
 * Zero-cost by design (CLAUDE.md): no network calls, no LLM. Given a set
 * of findings (package + severity + optional fixed versions), group by
 * package and propose the lowest version that resolves every finding for
 * that package. This module never executes anything, opens a PR, or
 * touches a repo — it only produces suggestions (`manifestHint` is text,
 * not a command that gets run).
 */
import { z } from 'zod';
import { EcosystemSchema, type Ecosystem } from '@aicc/shared';

export const PackageRefSchema = z.object({
  name: z.string().min(1).max(200),
  ecosystem: EcosystemSchema,
  version: z.string().min(1).max(100),
});

export const RemediationFindingSchema = z.object({
  id: z.string().max(128).optional(),
  cveId: z.string().max(32).optional(),
  package: PackageRefSchema,
  fixedVersions: z.array(z.string().max(100)).max(20).optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']),
});
export type RemediationFinding = z.infer<typeof RemediationFindingSchema>;

export const RemediationInputSchema = z.object({
  findings: z.array(RemediationFindingSchema).max(500).default([]),
});

export type Bump = 'none' | 'patch' | 'minor' | 'major' | 'unknown';
export type Risk = 'low' | 'medium' | 'high';

export interface Proposal {
  package: { name: string; ecosystem: Ecosystem };
  from: string;
  to: string;
  bump: Bump;
  resolves: string[];
  risk: Risk;
  manifestHint: string;
  status: 'ok' | 'manual_review';
}

export interface Unresolved {
  package: { name: string; ecosystem: Ecosystem };
  reason: string;
}

export interface RemediationResult {
  proposals: Proposal[];
  unresolved: Unresolved[];
  engine: 'heuristic';
  generatedAt: string;
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------
// npm/cargo/go/maven/nuget: semver-ish (MAJOR.MINOR.PATCH[.BUILD][-pre][+meta]).
// pypi: PEP440-ish (release segments + optional a/b/rc pre-release, .postN,
// .devN). Both are small, self-contained comparators — no new dependency.

interface SemverParsed {
  release: number[];
  pre?: string[];
}

function parseSemver(raw: string): SemverParsed | null {
  const m =
    /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
      raw.trim(),
    );
  if (!m) return null;
  const release = [m[1], m[2], m[3], m[4]].filter((p): p is string => p !== undefined).map(Number);
  return { release, pre: m[5] ? m[5].split('.') : undefined };
}

function comparePreIdentifiers(a: string[], b: string[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]);
    const bn = /^\d+$/.test(b[i]);
    if (an && bn) {
      const d = Number(a[i]) - Number(b[i]);
      if (d !== 0) return d;
    } else if (an !== bn) {
      return an ? -1 : 1;
    } else if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}

function compareSemver(a: SemverParsed, b: SemverParsed): number {
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    const d = (a.release[i] ?? 0) - (b.release[i] ?? 0);
    if (d !== 0) return d;
  }
  if (!a.pre && !b.pre) return 0;
  if (!a.pre) return 1;
  if (!b.pre) return -1;
  return comparePreIdentifiers(a.pre, b.pre);
}

interface Pep440Parsed {
  release: number[];
  phase: 0 | 1 | 2 | 3; // dev < pre < final < post
  phaseNum: number;
  preTag?: string;
}

function parsePep440(raw: string): Pep440Parsed | null {
  const m = /^(\d+(?:\.\d+)*)(?:(a|b|rc)(\d*))?(?:\.post(\d+))?(?:\.dev(\d+))?$/i.exec(raw.trim());
  if (!m) return null;
  const release = m[1].split('.').map(Number);
  if (m[5] !== undefined) return { release, phase: 0, phaseNum: Number(m[5]) };
  if (m[2] !== undefined)
    return { release, phase: 1, phaseNum: Number(m[3] || 0), preTag: m[2].toLowerCase() };
  if (m[4] !== undefined) return { release, phase: 3, phaseNum: Number(m[4]) };
  return { release, phase: 2, phaseNum: 0 };
}

function comparePep440(a: Pep440Parsed, b: Pep440Parsed): number {
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    const d = (a.release[i] ?? 0) - (b.release[i] ?? 0);
    if (d !== 0) return d;
  }
  if (a.phase !== b.phase) return a.phase - b.phase;
  if (a.phase === 1 && a.preTag !== b.preTag) {
    return (a.preTag ?? '') < (b.preTag ?? '') ? -1 : 1;
  }
  return a.phaseNum - b.phaseNum;
}

type ParsedVersion =
  { kind: 'semver'; value: SemverParsed } | { kind: 'pep440'; value: Pep440Parsed };

function parseVersion(ecosystem: Ecosystem, raw: string): ParsedVersion | null {
  if (ecosystem === 'pypi') {
    const value = parsePep440(raw);
    return value ? { kind: 'pep440', value } : null;
  }
  const value = parseSemver(raw);
  return value ? { kind: 'semver', value } : null;
}

/** Returns <0, 0, >0, or null if either version is unparseable. */
function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.kind === 'pep440' && b.kind === 'pep440') return comparePep440(a.value, b.value);
  if (a.kind === 'semver' && b.kind === 'semver') return compareSemver(a.value, b.value);
  // Mismatched kinds should not happen (both come from the same ecosystem).
  return 0;
}

function releaseOf(v: ParsedVersion): number[] {
  return v.kind === 'pep440' ? v.value.release : v.value.release;
}

function bumpType(from: ParsedVersion, to: ParsedVersion): Bump {
  const f = releaseOf(from);
  const t = releaseOf(to);
  if ((t[0] ?? 0) !== (f[0] ?? 0)) return 'major';
  if ((t[1] ?? 0) !== (f[1] ?? 0)) return 'minor';
  return 'patch';
}

const RISK_BY_BUMP: Record<Bump, Risk> = {
  none: 'low',
  major: 'high',
  minor: 'medium',
  patch: 'low',
  unknown: 'high',
};

// The hint is meant to be copied into a shell, so package names and
// versions must match each ecosystem's own identifier syntax; anything
// else gets no command at all.
const SAFE_NAME: Record<Ecosystem, RegExp> = {
  npm: /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/,
  pypi: /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  maven: /^[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+)?$/,
  go: /^[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*$/,
  cargo: /^[A-Za-z0-9_-]+$/,
  nuget: /^[A-Za-z0-9_.-]+$/,
};
const SAFE_VERSION = /^[A-Za-z0-9._+~-]+$/;

export function isSafeForHint(ecosystem: Ecosystem, name: string, version: string): boolean {
  return SAFE_NAME[ecosystem].test(name) && SAFE_VERSION.test(version);
}

function manifestHint(ecosystem: Ecosystem, name: string, to: string): string {
  if (!isSafeForHint(ecosystem, name, to)) {
    return 'manual update required: package name or version has unexpected characters';
  }
  switch (ecosystem) {
    case 'npm':
      return `npm install ${name}@${to}`;
    case 'pypi':
      return `pip install ${name}==${to}`;
    case 'maven':
      return `set <version>${to}</version> for ${name} in pom.xml`;
    case 'go':
      return `go get ${name}@${to.startsWith('v') ? to : `v${to}`}`;
    case 'cargo':
      return `cargo update -p ${name} --precise ${to}`;
    case 'nuget':
      return `dotnet add package ${name} --version ${to}`;
  }
}

// ---------------------------------------------------------------------------
// Proposal generation
// ---------------------------------------------------------------------------

function findingLabel(f: RemediationFinding): string {
  return f.cveId ?? f.id ?? 'unknown';
}

/** Deterministic, zero-cost remediation proposals. No network calls. */
export function proposeRemediation(input: unknown): RemediationResult {
  const { findings } = RemediationInputSchema.parse(input);

  const groups = new Map<
    string,
    { pkg: RemediationFinding['package']; findings: RemediationFinding[] }
  >();
  for (const f of findings) {
    const key = `${f.package.ecosystem}::${f.package.name}`;
    const existing = groups.get(key);
    if (existing) existing.findings.push(f);
    else groups.set(key, { pkg: f.package, findings: [f] });
  }

  const proposals: Proposal[] = [];
  const unresolved: Unresolved[] = [];

  for (const { pkg, findings: groupFindings } of groups.values()) {
    const packageRef = { name: pkg.name, ecosystem: pkg.ecosystem };
    const current = parseVersion(pkg.ecosystem, pkg.version);
    if (!current) {
      proposals.push({
        package: packageRef,
        from: pkg.version,
        to: pkg.version,
        bump: 'unknown',
        resolves: dedupe(groupFindings.map(findingLabel)),
        risk: 'high',
        manifestHint: `manual review required: cannot parse version "${pkg.version}" for ${pkg.ecosystem} package ${pkg.name}`,
        status: 'manual_review',
      });
      continue;
    }

    // For each finding, the minimum parseable fixed version that resolves it.
    const minFixPerFinding: ParsedVersion[] = [];
    let hasUnfixable = false;
    for (const f of groupFindings) {
      // Only a fix at or above the current version can resolve the finding;
      // a lower one belongs to another release line and says nothing about
      // the installed version.
      const candidates = (f.fixedVersions ?? [])
        .map((v) => parseVersion(pkg.ecosystem, v))
        .filter((v): v is ParsedVersion => v !== null && compareVersions(v, current) >= 0);
      if (candidates.length === 0) {
        hasUnfixable = true;
        break;
      }
      candidates.sort(compareVersions);
      minFixPerFinding.push(candidates[0]);
    }

    if (hasUnfixable) {
      unresolved.push({
        package: packageRef,
        reason: 'no fixed version at or above the installed version',
      });
      continue;
    }

    // The binding constraint is the highest of each finding's minimum fix.
    let target = current;
    for (const min of minFixPerFinding) {
      if (compareVersions(min, target) > 0) target = min;
    }

    const bump: Bump = compareVersions(target, current) === 0 ? 'none' : bumpType(current, target);
    const toRaw = target === current ? pkg.version : rawOf(target, groupFindings, pkg.ecosystem);

    proposals.push({
      package: packageRef,
      from: pkg.version,
      to: toRaw,
      bump,
      resolves: dedupe(groupFindings.map(findingLabel)),
      risk: RISK_BY_BUMP[bump],
      manifestHint: manifestHint(pkg.ecosystem, pkg.name, toRaw),
      status: 'ok',
    });
  }

  return {
    proposals,
    unresolved,
    engine: 'heuristic',
    generatedAt: new Date().toISOString(),
  };
}

/** Recover the original fixedVersions string for the chosen target parsed version. */
function rawOf(
  target: ParsedVersion,
  findings: RemediationFinding[],
  ecosystem: Ecosystem,
): string {
  for (const f of findings) {
    for (const raw of f.fixedVersions ?? []) {
      const parsed = parseVersion(ecosystem, raw);
      if (parsed && compareVersions(parsed, target) === 0) return raw;
    }
  }
  // Should not happen — target is always derived from a fixedVersions entry.
  return String(target.value.release.join('.'));
}

function dedupe(items: string[]): string[] {
  return Array.from(new Set(items));
}

// ---------------------------------------------------------------------------
// Applying a proposal
// ---------------------------------------------------------------------------

export const ApplyProposalSchema = z.object({
  package: z.object({ name: z.string().min(1).max(200), ecosystem: EcosystemSchema }),
  from: z.string().min(1).max(100),
  to: z.string().min(1).max(100),
  bump: z.enum(['none', 'patch', 'minor', 'major', 'unknown']),
  resolves: z.array(z.string().max(128)).max(50),
  risk: z.enum(['low', 'medium', 'high']),
  manifestHint: z.string().max(2000),
  status: z.enum(['ok', 'manual_review']),
});

export const ApplyContextSchema = z.object({
  findingId: z.string().max(128).optional(),
  cveId: z.string().max(32).optional(),
  assetId: z.string().max(128).optional(),
  repo: z.string().max(200).optional(),
});

export const ApplyInputSchema = z.object({
  integrationId: z.string().max(200).optional().default(''),
  proposal: ApplyProposalSchema,
  context: ApplyContextSchema.optional(),
  dryRun: z.boolean().optional(),
});

export interface ApplyInput {
  integrationId: string;
  proposal: Proposal;
  context?: { findingId?: string; cveId?: string; assetId?: string; repo?: string };
  dryRun?: boolean;
}

export interface ApplyResult {
  applied: boolean;
  integrationId: string;
  kind: 'issue' | 'pull_request' | null;
  url?: string;
  number?: number;
  message: string;
}

/**
 * `remediation.apply` — hands a proposal to the integration service, which
 * opens the GitHub issue/PR. The policy gates live here; the HTTP hop is
 * injected (`deps.callIntegration`) so this stays unit-testable offline.
 * Errors from the integration service propagate to the caller (the task
 * fails loudly rather than pretending nothing happened).
 */
export async function applyRemediation(
  input: ApplyInput,
  deps: { callIntegration: (body: unknown) => Promise<ApplyResult> },
): Promise<ApplyResult> {
  const integrationId = input.integrationId ?? '';
  if (!integrationId) {
    return {
      applied: false,
      integrationId: '',
      kind: null,
      message: 'integrationId is required to apply a remediation proposal',
    };
  }
  if (input.proposal.status !== 'ok') {
    return {
      applied: false,
      integrationId,
      kind: null,
      message:
        'proposal needs manual_review approval before it can be applied — remediation.apply only accepts proposals with status ok',
    };
  }
  return deps.callIntegration(input);
}
