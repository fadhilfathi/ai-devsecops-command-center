/**
 * Dependency-graph model — derived from one or more SBOMs.
 *
 * Round-trips with the Python Pydantic model maintained by
 * VulnerabilityIntelligenceAgent (S2.3). The graph is built
 * client-side from SBOM `dependencies[]` and joined with
 * vulnerability findings to produce transitive risk paths.
 *
 * Node IDs are the SBOM `bom-ref` strings (for components/sboms)
 * or vulnerability `id` strings (for vulnerability nodes). This
 * matches the join key used in the dashboard's "riskiest components"
 * aggregation.
 *
 * Risk weights are normalised 0..1; the `compositeScore` (0..100)
 * is computed downstream in `risk-score.model.ts`.
 */
import { z } from 'zod';

// ---------- enums ----------

export const GraphNodeTypeSchema = z.enum([
  'component',
  'sbom',
  'vulnerability',
  'license',
  'external-system',
]);
export type GraphNodeType = z.infer<typeof GraphNodeTypeSchema>;

export const GraphEdgeRelationSchema = z.enum([
  'depends_on',
  'uses',
  'vulnerable_to',
  'mitigated_by',
  'derived_from',
  'other',
]);
export type GraphEdgeRelation = z.infer<typeof GraphEdgeRelationSchema>;

// ---------- factor breakdown (mirrors risk-score.model.ts) ----------

export const RiskFactorBreakdownSchema = z.object({
  /** 0..1 — how severe the worst known issue is, normalised from CVSS */
  severity: z.number().min(0).max(1),
  /** 0..1 — EPSS probability in the worst case */
  epss: z.number().min(0).max(1),
  /** 0 or 1 — CISA KEV flag (binary) */
  kev: z.number().min(0).max(1),
  /** 0..1 — code reachability (1 = directly imported, 0.1 = transitive) */
  reachability: z.number().min(0).max(1),
  /** 0..1 — network/internet exposure (1 = public-facing service) */
  exposure: z.number().min(0).max(1),
});
export type RiskFactorBreakdown = z.infer<typeof RiskFactorBreakdownSchema>;

// ---------- nodes / edges ----------

export const GraphNodeSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  type: GraphNodeTypeSchema,
  /**
   * Node-type-specific attributes:
   *   - `component`:     `{ purl?, version?, ecosystem? }`
   *   - `sbom`:          `{ serialNumber? }`
   *   - `vulnerability`: `{ cveId?, severity?, cvssScore? }`
   */
  metadata: z.record(z.unknown()).optional(),
  /**
   * The SBOM `bom-ref` of the component this node represents, for
   * join-key consistency across the graph and the SBOM service.
   */
  bomRef: z.string().optional(),
});
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z.object({
  source: z.string().min(1),
  target: z.string().min(1),
  relation: GraphEdgeRelationSchema,
  /** Optional edge weight (used for `mitigated_by` strength, etc.) */
  weight: z.number().min(0).max(1).optional(),
  /** Source SBOM this edge was derived from, for traceability */
  sourceSbom: z.string().optional(),
});
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

// ---------- transitive paths ----------

export const TransitivePathSchema = z.object({
  /** Source node (typically the root component) */
  fromNodeId: z.string().min(1),
  /** Target node (typically a vulnerable component) */
  toNodeId: z.string().min(1),
  /** Ordered list of node IDs from `fromNodeId` to `toNodeId`, inclusive */
  path: z.array(z.string().min(1)).min(2),
  /** Risk contribution from this path (0..1) */
  risk: z.number().min(0).max(1),
  /** Vulnerability IDs reached along this path */
  vulnerabilityIds: z.array(z.string()).default([]),
});
export type TransitivePath = z.infer<typeof TransitivePathSchema>;

// ---------- per-node risk weight (sorted by `weight` desc in the dashboard) ----------

export const NodeRiskWeightSchema = z.object({
  nodeId: z.string().min(1),
  /** Normalised 0..1 weight, ranking input for the top-5 riskiest components */
  weight: z.number().min(0).max(1),
  factors: RiskFactorBreakdownSchema,
  /** Optional human-readable reason for the weight (used in dashboard tooltip) */
  rationale: z.string().max(500).optional(),
});
export type NodeRiskWeight = z.infer<typeof NodeRiskWeightSchema>;

// ---------- top-level graph ----------

export const DependencyGraphSchema = z.object({
  graphId: z.string().uuid(),
  generatedAt: z.string().datetime({ offset: true }),
  /** The SBOM serial number this graph was derived from (urn:uuid or just uuid) */
  rootSbomSerial: z.string().optional(),
  /** The `bom-ref` of the root component the graph is rooted at */
  rootBomRef: z.string().min(1),
  nodes: z.array(GraphNodeSchema).min(1),
  edges: z.array(GraphEdgeSchema).default([]),
  transitivePaths: z.array(TransitivePathSchema).default([]),
  riskWeights: z.array(NodeRiskWeightSchema).default([]),
  /** Model version that computed the weights (e.g. `risk-score-v1`) */
  modelVersion: z.string().default('risk-score-v1'),
}).passthrough();
export type DependencyGraph = z.infer<typeof DependencyGraphSchema>;

// ---------- service I/O shapes (used by S2.5 security-service proxy) ----------

/**
 * Request body for `POST /risk/calculate`.
 * Mirror: Pydantic `RiskCalculateRequest` in dependency_intel_service.
 */
export const RiskCalculateRequestSchema = z.object({
  /** SBOM to compute the risk graph over */
  sbom: z.object({
    bomFormat: z.literal('CycloneDX'),
    specVersion: z.string(),
    version: z.number().int(),
    metadata: z.unknown(),
    components: z.array(z.unknown()).default([]),
    dependencies: z.array(z.unknown()).default([]),
  }).passthrough(),
  /** Vulnerability findings to correlate (from vuln-intel-service) */
  vulnerabilities: z.array(z.unknown()).default([]),
  /** Optional tenant scoping */
  tenantId: z.string().uuid().optional(),
  /** Factor weights override; default weights are used if omitted */
  factorWeights: z.object({
    severity: z.number().min(0).max(1),
    epss: z.number().min(0).max(1),
    kev: z.number().min(0).max(1),
    reachability: z.number().min(0).max(1),
    exposure: z.number().min(0).max(1),
  }).refine((w) => {
    const sum = w.severity + w.epss + w.kev + w.reachability + w.exposure;
    return Math.abs(sum - 1) < 0.001;
  }, { message: 'factor weights must sum to 1.0' }).optional(),
});
export type RiskCalculateRequest = z.infer<typeof RiskCalculateRequestSchema>;

export const RiskCalculateResponseSchema = z.object({
  jobId: z.string().uuid(),
  status: z.enum(['queued', 'running', 'succeeded', 'failed']),
  startedAt: z.string().datetime({ offset: true }),
  finishedAt: z.string().datetime({ offset: true }).optional(),
  graph: DependencyGraphSchema.optional(),
  error: z.string().optional(),
});
export type RiskCalculateResponse = z.infer<typeof RiskCalculateResponseSchema>;

// ---------- JSON-Schema export helper ----------

export function toJSONSchema<T extends z.ZodType>(schema: T): Record<string, unknown> {
  return z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/security/' },
  }) as Record<string, unknown>;
}
