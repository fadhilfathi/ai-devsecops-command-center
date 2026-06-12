/**
 * Security event-bus topic constants.
 *
 * Used by:
 *   - `security-service` to publish `SecuritySbomGeneratedEvent`, etc.
 *   - The agent runtime and downstream consumers to subscribe.
 *   - The Python agents (mirrored as `SECURITY_SBOM_TOPIC` etc. in Python).
 *
 * **Naming convention (S2.9 alignment, 2026-06-12; locked by GitOpsManager O-3.5):**
 *   - Prefix: `security.` (reverse-DNS style, CloudEvents-friendly)
 *   - Shape: `<domain>.<aggregate>.<event>.vN` — per `docs/architecture/event-bus.md` §5,
 *     ADR-0003, and the S2.10 system map. The `.vN` suffix is the canonical
 *     version marker for the bus subject / Redis Stream key.
 *   - Source: `security-service` (security-service :4003 is the only emitter;
 *     the bus wraps the typed event payload in a CloudEvents v1.0 envelope)
 *   - **All 4 topics are at `.v1` as of 2026-06-12.** The next breaking change
 *     to the event shape will bump to `.v2` and the old topic will be
 *     retired after a 2-release deprecation window.
 *   - **NB:** the `.v1` suffix is for Redis Stream subjects and the
 *     `github-bridge` event_type mapping ONLY. GitHub
 *     `repository_dispatch` event types (`vulnerability-detected`,
 *     `supported-version-released`) are a different namespace and do NOT
 *     get the `.v1` suffix. The github-bridge service maps the Redis
 *     Stream subject to the GitHub `event_type` in the bridge, not the
 *     consumer workflow.
 *   - All security-domain events carry a `tenantId` field for multi-tenant
 *     isolation. The security-service stamps it from the authenticated
 *     request headers (NOT from upstream feeds).
 *
 * **Why a separate `SCAN_TOPIC` (and not just `SBOM_TOPIC`):**
 *   - A scan can complete without producing an SBOM (e.g., a SAST or
 *     runtime scan), and an SBOM can be generated without a full scan
 *     (e.g., a fresh filesystem scan of a lockfile). Decoupling the
 *     two events lets ComplianceOfficer's `scan-listener.ts` subscribe
 *     to a precise trigger for POA&M auto-mapping.
 */
export const SBOM_TOPIC = 'security.sbom.generated.v1' as const;
export const VULN_TOPIC = 'security.vulnerability.detected.v1' as const;
export const RISK_TOPIC = 'security.risk.calculated.v1' as const;
/**
 * Emitted when a security scan completes (SCA, SAST, container, runtime, etc.).
 * Subscribed by ComplianceOfficer's `scan-listener.ts` for POA&M auto-mapping.
 * The `assetId` field on the data is the primary key for evidence records.
 */
export const SCAN_TOPIC = 'security.scan.completed.v1' as const;

export const SECURITY_TOPICS = {
  SBOM_TOPIC,
  VULN_TOPIC,
  RISK_TOPIC,
  SCAN_TOPIC,
} as const;

export type SecurityTopic = (typeof SECURITY_TOPICS)[keyof typeof SECURITY_TOPICS];

/**
 * Per-event payload types. The bus wraps each of these in a CloudEvents
 * v1.0 envelope (`{ type, version, source, tenantId, severity, data }`)
 * at publish time. Consumers receive `{ ...envelope, data: TEvent }`.
 *
 * Migration note (Sprint 2 S2.9): the `assetId` field was added to all
 * 4 events on 2026-06-12 per ComplianceOfficer's POA&M evidence-record
 * requirements. It is OPTIONAL on the 3 existing events (back-compat
 * with current emitters) and REQUIRED on `SecurityScanCompletedEvent`
 * (new event). Sprint 2.1 may add a generic `subjectKind` discriminator.
 */
export interface SecuritySbomGeneratedEvent {
  sbomId: string;
  tenantId: string;
  rootBomRef: string;
  /** Asset id of what was scanned (image:tag, repo:branch, fs:path). Optional for back-compat. */
  assetId?: string;
  specVersion: string;
  componentCount: number;
  generatedAt: string;
  source: 'sbom-pipeline-service';
}

export interface SecurityVulnerabilityDetectedEvent {
  vulnerabilityId: string;
  tenantId: string;
  affectedBomRefs: string[];
  /**
   * Per-affected first-known-vulnerable version range, parallel to `affectedBomRefs`.
   * Position `i` corresponds to `affectedBomRefs[i]`. `null` if unknown.
   * Sourced from NVD/GHSA/OSV (per-version). Sprint 2.9 alignment with ComplianceOfficer.
   */
  affectedIntroducedIn?: (string | null)[];
  /**
   * Per-affected tenant-side introducedAt (ISO-8601 with offset), parallel to `affectedBomRefs`.
   * Position `i` corresponds to `affectedBomRefs[i]`. `null` if unknown.
   * Sourced from tenant-side scanner / SBOM tool / dependency-intel (per-deploy).
   * ComplianceOfficer's `effectiveIntroducedAt()` helper takes `introducedAt ?? introducedIn ?? null` so the fresher tenant-side signal wins.
   */
  affectedIntroducedAt?: (string | null)[];
  /** Asset id of the scanned target. Optional for fan-out cases (one CVE across many assets). */
  assetId?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  cvssScore?: number;
  kev: boolean;
  /** Discriminator for SCA / SAST / runtime / container / iac. S2.9; default 'sca' if absent. */
  kind?: 'sca' | 'sast' | 'runtime' | 'container' | 'iac';
  detectedAt: string;
  source: 'vuln-intel-service' | 'security-service';
}

export interface SecurityRiskCalculatedEvent {
  riskScoreId: string;
  tenantId: string;
  subjectKind: 'component' | 'sbom' | 'vulnerability';
  subjectId: string;
  /** Asset id of the scored SBOM. Optional. */
  assetId?: string;
  compositeScore: number;
  computedAt: string;
  source: 'dependency-intel-service' | 'security-service';
}

/**
 * Emitted when a security scan completes for an asset. Subscribed by
 * ComplianceOfficer's `scan-listener.ts` for POA&M auto-mapping.
 *
 * The `findings[]` array uses the canonical `Vulnerability` shape from
 * `@aicc/shared/security` (Zod schema in `models/security/vulnerability.model.ts`).
 * The optional `sbom` and `scanReport` strings are raw JSON (CycloneDX /
 * scanner-native) for evidence attachment — they are NOT parsed at emit
 * time to avoid double-decoding and to keep the event payload small.
 */
export interface SecurityScanCompletedEvent {
  scanId: string;
  /** The asset id that was scanned (image:tag, repo:branch, host:id). REQUIRED. */
  assetId: string;
  tenantId: string;
  scanner:
    | 'trivy'
    | 'grype'
    | 'syft'
    | 'checkov'
    | 'semgrep'
    | 'codeql'
    | 'falco'
    | 'other';
  /** Vulnerabilities found, in canonical Vulnerability shape. */
  findings: import('@aicc/shared/security').Vulnerability[];
  /** Raw SBOM (CycloneDX JSON string) — when the scan produced one. */
  sbom?: string;
  /** Raw scanner report (JSON string) for evidence attachment (POA&M evidence). */
  scanReport?: string;
  /** Per-affected-entry firstSeen timestamps, if tracked. */
  firstSeenAt?: string;
  /** ISO 8601 UTC of when the scan completed. */
  detectedAt: string;
  source:
    | 'sbom-pipeline-service'
    | 'vuln-intel-service'
    | 'dependency-intel-service'
    | 'security-service';
}
