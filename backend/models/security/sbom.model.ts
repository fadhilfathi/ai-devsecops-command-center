/**
 * SBOM model — CycloneDX 1.5 / 1.6 wire-compatible.
 *
 * Round-trips with the Python Pydantic model maintained by
 * SBOMPipelineAgent (S2.1). Field names match the CycloneDX JSON
 * wire format exactly (kebab-case for `bom-ref`, `mime-type`, etc.)
 * so that JSON.parse → zod.validate is a 1:1 passthrough.
 *
 * Each Zod schema exports:
 *   - the schema itself (for `z.parse` / `z.safeParse`)
 *   - the inferred TypeScript type (`z.infer<typeof XxxSchema>`)
 *   - a JSON-Schema fragment (for OpenAPI registration and Python codegen)
 *
 * `.passthrough()` is enabled on the top-level `Sbom` so that
 * CycloneDX extensions (e.g. `vulnerabilities`, `compositions`,
 * `annotations`, `formulation`, `declarations`) round-trip cleanly
 * without us enumerating them in Sprint 2.
 */
import { z } from 'zod';

// ---------- enums ----------

export const SbomComponentTypeSchema = z.enum([
  'application',
  'framework',
  'library',
  'container',
  'platform',
  'operating-system',
  'device',
  'device-driver',
  'firmware',
  'file',
  'machine-learning-model',
  'data',
  'cryptographic-asset',
]);
export type SbomComponentType = z.infer<typeof SbomComponentTypeSchema>;

export const SbomHashAlgorithmSchema = z.enum([
  'MD5',
  'SHA-1',
  'SHA-256',
  'SHA-384',
  'SHA-512',
  'SHA3-256',
  'SHA3-384',
  'SHA3-512',
  'BLAKE2b-256',
  'BLAKE2b-384',
  'BLAKE2b-512',
  'BLAKE3',
]);
export type SbomHashAlgorithm = z.infer<typeof SbomHashAlgorithmSchema>;

export const SbomLicenseChoiceSchema = z.enum([
  'declared',
  'observed',
  'requested',
  'evaluated',
  'original',
]);
export type SbomLicenseChoice = z.infer<typeof SbomLicenseChoiceSchema>;

// ---------- primitives ----------

export const SbomHashSchema = z.object({
  alg: SbomHashAlgorithmSchema,
  /** Hex-encoded hash content (no `0x` prefix). */
  content: z.string().min(1),
});
export type SbomHash = z.infer<typeof SbomHashSchema>;

export const SbomLicenseExpressionSchema = z.object({
  expression: z.string().min(1),
  // CycloneDX also supports `acknowledgements`; pass-through handled at top level
});
export type SbomLicenseExpression = z.infer<typeof SbomLicenseExpressionSchema>;

export const SbomLicenseSchema = z.union([
  z.object({
    license: z.object({
      id: z.string().optional(),
      name: z.string().optional(),
      text: z.union([z.object({ contentType: z.string(), encoding: z.string(), content: z.string() }), z.string()]).optional(),
      url: z.string().url().optional(),
    }).optional(),
    expression: SbomLicenseExpressionSchema.optional(),
    choice: SbomLicenseChoiceSchema.optional(),
  }),
  z.string(), // bare SPDX id shorthand e.g. "MIT"
]);
export type SbomLicense = z.infer<typeof SbomLicenseSchema>;

// ---------- component ----------

/**
 * Note: `bom-ref` uses kebab-case key to match the CycloneDX JSON
 * wire format. Access in TS as `component['bom-ref']`. The Pydantic
 * mirror uses `Field(alias="bom-ref")`.
 */
export const SbomComponentSchema = z.object({
  type: SbomComponentTypeSchema,
  'bom-ref': z.string().min(1),
  name: z.string().min(1),
  group: z.string().optional(),
  version: z.string().optional(),
  /** Package URL — see https://github.com/package-url/purl-spec */
  purl: z.string().optional(),
  /** Common Platform Enumeration identifier */
  cpe: z.string().optional(),
  description: z.string().optional(),
  scope: z.enum(['required', 'optional', 'excluded']).optional(),
  licenses: z.array(SbomLicenseSchema).optional(),
  hashes: z.array(SbomHashSchema).optional(),
  supplier: z.union([
    z.object({ name: z.string(), url: z.string().url().optional(), contact: z.array(z.object({ name: z.string().optional(), email: z.string().email().optional(), phone: z.string().optional() })).optional() }),
    z.string(),
  ]).optional(),
  manufacturer: z.union([
    z.object({ name: z.string(), url: z.string().url().optional(), contact: z.array(z.object({ name: z.string().optional(), email: z.string().email().optional(), phone: z.string().optional() })).optional() }),
    z.string(),
  ]).optional(),
  copyright: z.array(z.object({ text: z.string() })).optional(),
  /** Pedigree: ancestors, descendants, variants */
  pedigree: z.object({
    ancestors: z.array(z.lazy(() => SbomComponentSchema)).optional(),
    descendants: z.array(z.lazy(() => SbomComponentSchema)).optional(),
    variants: z.array(z.lazy(() => SbomComponentSchema)).optional(),
  }).optional(),
  /** External reference (e.g. vcs, issue-tracker, documentation) */
  externalReferences: z.array(z.object({
    type: z.enum(['vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation', 'support', 'distribution', 'license', 'build-meta', 'release-notes', 'security-contact', 'other']),
    url: z.string().url(),
    comment: z.string().optional(),
  })).optional(),
  /** Properties (key/value tags) */
  properties: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
});
export type SbomComponent = z.infer<typeof SbomComponentSchema>;

// ---------- dependency ----------

export const SbomDependencySchema = z.object({
  /** `bom-ref` of the dependent component */
  ref: z.string().min(1),
  /** `bom-ref` values of components this one depends on */
  dependsOn: z.array(z.string().min(1)).default([]),
});
export type SbomDependency = z.infer<typeof SbomDependencySchema>;

// ---------- metadata ----------

export const SbomToolSchema = z.object({
  vendor: z.string().optional(),
  name: z.string().min(1),
  version: z.string().optional(),
  hashes: z.array(SbomHashSchema).optional(),
});
export type SbomTool = z.infer<typeof SbomToolSchema>;

export const SbomAuthorSchema = z.object({
  name: z.string().min(1),
  email: z.string().email().optional(),
  phone: z.string().optional(),
});
export type SbomAuthor = z.infer<typeof SbomAuthorSchema>;

export const SbomMetadataSchema = z.object({
  timestamp: z.string().datetime({ offset: true }),
  tools: z.object({ components: z.array(SbomToolSchema) }).optional(),
  authors: z.array(SbomAuthorSchema).optional(),
  /** The root component this SBOM describes */
  component: SbomComponentSchema.optional(),
  manufacture: z.union([z.object({ name: z.string(), url: z.string().url().optional() }), z.string()]).optional(),
  supplier: z.union([z.object({ name: z.string(), url: z.string().url().optional() }), z.string()]).optional(),
  /** CycloneDX licenses — global scope */
  licenses: z.array(SbomLicenseSchema).optional(),
  /** Properties (top-level metadata) */
  properties: z.array(z.object({ name: z.string(), value: z.string() })).optional(),
});
export type SbomMetadata = z.infer<typeof SbomMetadataSchema>;

// ---------- top-level SBOM ----------

export const SbomSchema = z.object({
  bomFormat: z.literal('CycloneDX'),
  specVersion: z.string().regex(/^\d+\.\d+$/),
  version: z.number().int().min(1),
  /** urn:uuid — globally unique SBOM serial number */
  serialNumber: z.string().regex(/^urn:uuid:[0-9a-f-]{36}$/i).optional(),
  metadata: SbomMetadataSchema,
  components: z.array(SbomComponentSchema).default([]),
  dependencies: z.array(SbomDependencySchema).default([]),
}).passthrough();
export type Sbom = z.infer<typeof SbomSchema>;

// ---------- service I/O shapes (used by S2.5 security-service proxy) ----------

/**
 * Request body for `POST /sbom/generate`.
 * Mirror: Pydantic `SbomGenerateRequest` in sbom_pipeline_service.
 */
export const SbomGenerateRequestSchema = z.object({
  /** Source to scan */
  source: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('container'), image: z.string().min(1), pullSecret: z.string().optional() }),
    z.object({ kind: z.literal('git'), url: z.string().url(), ref: z.string().optional(), depth: z.number().int().positive().optional() }),
    z.object({ kind: z.literal('filesystem'), path: z.string().min(1) }),
    z.object({ kind: z.literal('sbom'), existing: SbomSchema }),
  ]),
  /** Optional tenant scoping; defaults to request header */
  tenantId: z.string().uuid().optional(),
  /** Whether to follow transitive dependencies (default true) */
  transitive: z.boolean().default(true),
  /** Preferred output format (CycloneDX default; SPDX is a future option) */
  format: z.enum(['cyclonedx']).default('cyclonedx'),
  /** CycloneDX spec version (default 1.5) */
  specVersion: z.string().regex(/^\d+\.\d+$/).default('1.5'),
});
export type SbomGenerateRequest = z.infer<typeof SbomGenerateRequestSchema>;

/**
 * Request body for `POST /sbom/analyze`.
 * Mirror: Pydantic `SbomAnalyzeRequest` in sbom_pipeline_service.
 */
export const SbomAnalyzeRequestSchema = z.object({
  sbom: SbomSchema,
  /** Components to focus on; default = all root components */
  focus: z.array(z.string()).optional(),
  /** Whether to compute license compatibility matrix (default false) */
  licenseMatrix: z.boolean().default(false),
  /** Whether to flag outdated dependencies (default true) */
  outdated: z.boolean().default(true),
});
export type SbomAnalyzeRequest = z.infer<typeof SbomAnalyzeRequestSchema>;

/** Analysis report — license + freshness summary per component. */
export const SbomAnalysisComponentSchema = z.object({
  bomRef: z.string(),
  name: z.string(),
  version: z.string().optional(),
  licenses: z.array(SbomLicenseSchema).optional(),
  isOutdated: z.boolean().optional(),
  latestVersion: z.string().optional(),
  /** Number of distinct licenses in the transitive closure of this component */
  transitiveLicenseCount: z.number().int().nonnegative().optional(),
});
export type SbomAnalysisComponent = z.infer<typeof SbomAnalysisComponentSchema>;

export const SbomAnalysisReportSchema = z.object({
  generatedAt: z.string().datetime({ offset: true }),
  totalComponents: z.number().int().nonnegative(),
  outdatedCount: z.number().int().nonnegative().default(0),
  licenseConflicts: z.array(z.object({
    bomRef: z.string(),
    licenses: z.array(z.string()),
    reason: z.string(),
  })).default([]),
  components: z.array(SbomAnalysisComponentSchema),
});
export type SbomAnalysisReport = z.infer<typeof SbomAnalysisReportSchema>;

/** Response shape for `POST /sbom/generate` and `POST /sbom/analyze`. */
export const SbomServiceResponseSchema = z.object({
  jobId: z.string().uuid(),
  status: z.enum(['queued', 'running', 'succeeded', 'failed']),
  startedAt: z.string().datetime({ offset: true }),
  finishedAt: z.string().datetime({ offset: true }).optional(),
  sbom: SbomSchema.optional(),
  report: SbomAnalysisReportSchema.optional(),
  error: z.string().optional(),
});
export type SbomServiceResponse = z.infer<typeof SbomServiceResponseSchema>;

// ---------- JSON-Schema export helper ----------

/**
 * Emit a JSON Schema (draft 2020-12) for a Zod schema. Used by:
 *   - security-service's OpenAPI registration (`@fastify/swagger`)
 *   - Python Pydantic codegen (manual, not in this file)
 */
export function toJSONSchema<T extends z.ZodType>(schema: T): Record<string, unknown> {
  return z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    metadata: { $id: 'https://aicc.local/schemas/security/' },
  }) as Record<string, unknown>;
}
