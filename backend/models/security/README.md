# Security Data Models (S2.4)

Canonical home for the security domain contracts shared between
**TypeScript services** and the **Python agents** (`sbom-pipeline-service`,
`vuln-intel-service`, `dependency-intel-service`).

## Layout

```
backend/models/security/
├── index.ts                    # barrel re-export
├── sbom.model.ts               # CycloneDX 1.5/1.6 SBOM + generate/analyze I/O
├── vulnerability.model.ts      # NVD/GHSA/OSV/Snyk normalised vuln + ingest I/O
├── dependency-graph.model.ts   # graph nodes/edges/transitive paths + risk/calculate I/O
└── risk-score.model.ts         # composite 0-100 score + top-5/dashboard I/O
```

## How to consume (TypeScript)

```typescript
import {
  SbomSchema,
  VulnerabilitySchema,
  DependencyGraphSchema,
  RiskScoreSchema,
  SecurityDashboardResponseSchema,
  computeCompositeScore,
  DEFAULT_RISK_FACTOR_WEIGHTS,
  toJSONSchema,
} from '../../../models/security/index.js';

// Validate an upstream payload
const sbom = SbomSchema.parse(await upstreamResponse.json());

// Export as JSON Schema for OpenAPI / Python codegen
const jsonSchema = toJSONSchema(VulnerabilitySchema);
```

## How to consume (Python)

The Python agents must mirror these contracts in Pydantic. The
field-by-field mapping is in the message threads with
`SBOMPipelineAgent` and `VulnerabilityIntelligenceAgent` (Sprint 2
kickoff). Compatibility rules:

| Rule | Description |
|---|---|
| **Field names** | Match the wire format exactly. `bom-ref` is kebab in JSON; Zod uses the kebab key `'bom-ref'`. Pydantic uses `Field(alias="bom-ref")` with `populate_by_name=True`. |
| **Optional fields** | Default to `None` (Python) / `undefined` (TS), never `null`. Use `.optional()` not `.nullable()` in Zod. |
| **Top-level passthrough** | The top-level Zod schemas use `.passthrough()` so upstream extensions round-trip cleanly. Pydantic uses `model_config = ConfigDict(extra="allow")`. |
| **JSON Schema export** | Each module exports `toJSONSchema(schema)` for OpenAPI registration in `security-service` and as a stable reference for Pydantic codegen. |
| **Timestamps** | ISO 8601 with offset (`z.string().datetime({ offset: true })`). |
| **Semver** | `SemverRangeSchema.expression` is a string (e.g. `>=1.0.0, <1.2.0`); `events[]` is the OSV-style structured alternative. |

## Event topic constants (consumed by `@aicc/shared/security`)

| Constant | Value | Emitted when |
|---|---|---|
| `SBOM_TOPIC` | `security.sbom.generated` | A new SBOM is generated and stored |
| `VULN_TOPIC` | `security.vulnerability.detected` | A vulnerability is correlated to a component |
| `RISK_TOPIC` | `security.risk.calculated` | A composite risk score is computed |

## Validation matrix

| Source of truth | Zod | Python | JSON wire |
|---|---|---|---|
| SBOM shape | `SbomSchema` | `Sbom` (Pydantic) | CycloneDX 1.5/1.6 |
| Vulnerability shape | `VulnerabilitySchema` | `Vulnerability` (Pydantic) | OSV + extensions |
| Graph shape | `DependencyGraphSchema` | `DependencyGraph` (Pydantic) | internal |
| Risk score | `RiskScoreSchema` | `RiskScore` (Pydantic) | internal |
| Dashboard | `SecurityDashboardResponseSchema` | n/a (TS-only) | internal |

## Coordinate via these message threads

- **SBOM** with `SBOMPipelineAgent` — field shape, bom-ref strategy,
  `POST /sbom/generate` request body.
- **Vulnerability + Graph + Risk** with `VulnerabilityIntelligenceAgent` —
  transitive-path semantics, EPSS caching, `POST /vulnerabilities/ingest`
  and `POST /risk/calculate` request bodies, top-5 ranking order.
