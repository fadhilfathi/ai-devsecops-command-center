/**
 * Domain models for the AI-DevSecOps Command Center.
 *
 * These are intentionally simple for the Sprint 1 skeleton — they will
 * evolve as the SecurityArchitect and ComplianceOfficer agents finalize
 * their respective designs.
 */

import type { BaseEntity, Severity, TenantScoped, UUID } from './common.js';

export type UserRole =
  | 'platform_admin'
  | 'security_analyst'
  | 'compliance_officer'
  | 'developer'
  | 'viewer';

export interface User extends BaseEntity, TenantScoped {
  email: string;
  displayName: string;
  role: UserRole;
  active: boolean;
}

export type AssetType = 'repository' | 'service' | 'container' | 'vm' | 'saas';

export interface Asset extends BaseEntity, TenantScoped {
  type: AssetType;
  name: string;
  ownerId: UUID;
  metadata: Record<string, unknown>;
  tags: string[];
}

export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface SecurityScan extends BaseEntity, TenantScoped {
  assetId: UUID;
  status: ScanStatus;
  startedAt?: string;
  finishedAt?: string;
  findingsCount: number;
  scanner: string;
}

export type FindingSeverity = Severity;

export interface VulnerabilityFinding extends BaseEntity, TenantScoped {
  scanId: UUID;
  cveId?: string;
  packageName?: string;
  packageVersion?: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  remediation?: string;
  status: 'open' | 'triaging' | 'in_progress' | 'resolved' | 'suppressed';
}

export type IncidentSeverity = Severity;
export type IncidentStatus = 'open' | 'acknowledged' | 'mitigating' | 'resolved' | 'closed';

export interface Incident extends BaseEntity, TenantScoped {
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assigneeId?: UUID;
  relatedFindingIds: UUID[];
  runbookId?: UUID;
}

export interface Runbook extends BaseEntity, TenantScoped {
  name: string;
  description: string;
  steps: Array<{ order: number; title: string; detail: string }>;
  triggers: string[];
}

export type ComplianceFramework = 'cis_v8' | 'nist_800_53' | 'soc2' | 'iso_27001';

export interface ComplianceControl extends BaseEntity, TenantScoped {
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  status: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
  evidenceRefs: string[];
}

export type IntegrationProvider = 'github' | 'gitlab' | 'bitbucket' | 'jira' | 'slack';

export interface Integration extends BaseEntity, TenantScoped {
  provider: IntegrationProvider;
  name: string;
  config: Record<string, unknown>;
  enabled: boolean;
  lastSyncAt?: string;
}
