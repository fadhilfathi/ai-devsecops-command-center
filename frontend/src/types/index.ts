/**
 * Shared TypeScript types used across the AionUi frontend.
 *
 * These mirror the contracts published by the six backend services
 * (auth, agent, security, incident, compliance, integration). When
 * the API gateway emits OpenAPI, we can codegen these from it.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AssetKind =
  | "repository"
  | "service"
  | "container"
  | "identity"
  | "data-store"
  | "saas-account";

export type Asset = {
  id: string;
  name: string;
  kind: AssetKind;
  owner: string;
  environment: "prod" | "staging" | "dev" | "sandbox";
  criticality: Severity;
  lastSeen: string; // ISO
  tags: string[];
};

export type Vulnerability = {
  id: string; // CVE-XXXX-XXXXX or internal ID
  cve?: string;
  title: string;
  severity: Severity;
  cvss: number;
  package: string;
  version: string;
  fixedIn?: string;
  status: "open" | "triaged" | "in-progress" | "remediated" | "accepted";
  assetId: string;
  detectedAt: string;
};

export type Incident = {
  id: string;
  title: string;
  severity: Severity;
  status: "open" | "investigating" | "contained" | "resolved" | "postmortem";
  assignee: string;
  source: "github" | "siem" | "agent" | "user" | "cloud";
  createdAt: string;
  updatedAt: string;
  summary: string;
};

export type SbomComponent = {
  id: string;
  name: string;
  version: string;
  purl: string; // package URL
  license: string;
  supplier?: string;
  vulnerabilities: number;
};

export type ComplianceControl = {
  id: string;
  family: string; // e.g. "CIS 5 — Access Control"
  framework: "CISv8" | "NIST-800-53" | "SOC2" | "ISO-27001";
  title: string;
  status: "pass" | "fail" | "partial" | "not-assessed";
  evidenceCount: number;
  lastAssessedAt: string;
};

export type Integration = {
  id: string;
  name: string;
  category: "scm" | "ci" | "ticketing" | "chat" | "cloud" | "siem" | "iam";
  vendor: string;
  status: "connected" | "needs-attention" | "disconnected";
  lastSyncAt?: string;
};

export type Kpi = {
  label: string;
  value: string;
  delta?: number; // percent
  trend?: "up" | "down" | "flat";
  hint?: string;
};

export type EventStreamEntry = {
  id: string;
  ts: string;
  source: "agent" | "github" | "siem" | "system" | "user";
  level: Severity;
  message: string;
};
