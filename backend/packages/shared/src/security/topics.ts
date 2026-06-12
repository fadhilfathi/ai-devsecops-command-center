/**
 * Security event-bus topic constants.
 *
 * Used by:
 *   - `security-service` to publish `VulnerabilityDetected` etc.
 *   - The agent runtime and downstream consumers to subscribe.
 *   - The Python agents (mirrored as `SECURITY_SBOM_TOPIC` etc. in Python).
 *
 * Naming: `<domain>.<aggregate>.<event>` — matches the event-bus design
 * owned by PlatformArchitect (Sprint 1, `docs/architecture/event-bus.md`).
 */
export const SBOM_TOPIC = 'security.sbom.generated' as const;
export const VULN_TOPIC = 'security.vulnerability.detected' as const;
export const RISK_TOPIC = 'security.risk.calculated' as const;

export const SECURITY_TOPICS = {
  SBOM_TOPIC,
  VULN_TOPIC,
  RISK_TOPIC,
} as const;

export type SecurityTopic = (typeof SECURITY_TOPICS)[keyof typeof SECURITY_TOPICS];

/**
 * Optional: per-event payload type aliases for the event bus.
 * The runtime payload is `unknown` and validated by the consumer
 * using the matching Zod schema from `models.ts`.
 */
export interface SecuritySbomGeneratedEvent {
  sbomId: string;
  tenantId: string;
  rootBomRef: string;
  specVersion: string;
  componentCount: number;
  generatedAt: string;
  source: 'sbom-pipeline-service';
}

export interface SecurityVulnerabilityDetectedEvent {
  vulnerabilityId: string;
  tenantId: string;
  affectedBomRefs: string[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
  cvssScore?: number;
  kev: boolean;
  detectedAt: string;
  source: 'vuln-intel-service' | 'security-service';
}

export interface SecurityRiskCalculatedEvent {
  riskScoreId: string;
  tenantId: string;
  subjectKind: 'component' | 'sbom' | 'vulnerability';
  subjectId: string;
  compositeScore: number;
  computedAt: string;
  source: 'dependency-intel-service' | 'security-service';
}
