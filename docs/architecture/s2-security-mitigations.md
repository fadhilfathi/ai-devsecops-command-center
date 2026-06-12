# S2 Security Mitigations — security-service Extensions

> **Document Owner:** SecurityArchitect
> **Sprint:** 2 (S2.8)
> **Status:** Approved for implementation
> **Last Updated:** 2026-06-12
> **Related:** [security-stack-threat-model.md](./security-stack-threat-model.md) | [s2-test-plan.md](../security/s2-test-plan.md) | [authentication-and-security-design.md](./authentication-and-security-design.md)

## 1. Findings

- The threat model (`security-stack-threat-model.md`) identified 9 cross-cutting threats. Of those, 6 are mitigated by **input-side** controls that the security-service must enforce at the API boundary.
- The remaining 3 (Syft supply chain, CVE feed integrity, LLM prompt injection) are mitigated by **runtime-side** controls in the Python services and are documented here for the SBOMPipelineAgent and VulnerabilityIntelligenceAgent.
- All controls below are **drop-in middleware** in the existing Fastify security-service. No new service is required.
- The mitigations must be **unit + integration tested** before S2.11 (end-to-end validation); the test plan is in `docs/security/s2-test-plan.md`.

## 2. Decisions

- **All input validation is centralized** in `src/middleware/sbom-input.ts`. Both the Fastify router and the Python services validate the same PURL regex, the same component-name regex, and the same size limits — definitions are in `@aicc/security-contracts` so Node and Python share a single source of truth.
- **Rate limiting uses Redis token buckets** at the Fastify layer; the key is `ratelimit:{tenant_id}:{bucket}` with a Lua script for atomic check-and-decrement.
- **Sandbox manifests are provided as kustomize overlays** under `infra/sandbox/sbom-scanner/`. The base manifest is the same for dev/stage/prod; the overlays only add environment-specific NetworkPolicies and resource limits.
- **Cosign verification is in a startup hook**, not in the request path. The Syft image digest is verified before the pod accepts traffic; a startup failure causes CrashLoopBackOff.
- **CVE feed validation is in a sidecar job** that runs per-feed; the main service consumes only the validated, signed, versioned records from Postgres.
- **The risk-score audit log uses the same hash-chain format** as the rest of the platform (see `authentication-and-security-design.md` § 12.2). Coordination with ComplianceOfficer confirmed: retention 7y, hot 90d, warm 1y, cold 7y; format is JSONL.

## 3. Deliverables

### 3.1 PURL regex and component-name validation

**File:** `backend/services/security/src/middleware/sbom-input.ts`

```typescript
// SPDX-License-Identifier: Apache-2.0
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

// PURL spec grammar (simplified, case-sensitive on type, lowercase on namespace)
// Reference: https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.md
const PURL_RE =
  /^pkg:[a-z][a-z0-9+.\-]*\/[A-Za-z0-9.\-_~+@%]+(?:@[A-Za-z0-9.\-_~+]+)?(?:\?[^#\s]+)?(?:#[A-Za-z0-9.\-_~+]+)?$/;

// CycloneDX component name rules:
//   - 1..214 chars
//   - letters, digits, '.', '_', '-'
//   - no whitespace, no control chars
const COMPONENT_NAME_RE = /^[A-Za-z0-9._-]{1,214}$/;

const MAX_SBOM_BYTES = 10 * 1024 * 1024;          // 10 MB
const MAX_COMPONENTS = 5_000;
const MAX_DEPENDENCIES = 5_000;                   // distinct declared deps
const MAX_EDGES = 100_000;
const MAX_DEPTH = 20;

export class SbomValidationError extends Error {
  constructor(public code: string, public field: string, message: string) {
    super(message);
    this.name = 'SbomValidationError';
  }
}

function assertPurl(purl: unknown, field: string): void {
  if (typeof purl !== 'string' || !PURL_RE.test(purl)) {
    throw new SbomValidationError('sbom.purl.invalid', field, 'invalid PURL');
  }
}

function assertName(name: unknown, field: string): void {
  if (typeof name !== 'string' || !COMPONENT_NAME_RE.test(name)) {
    throw new SbomValidationError('sbom.component.name.invalid', field,
      'component name must match ' + COMPONENT_NAME_RE.source);
  }
}

export const sbomInputMiddleware: FastifyPluginAsync = fp(async (app) => {
  app.addContentTypeParser(
    'application/vnd.cyclonedx+json',
    { parseAs: 'string', bodyLimit: MAX_SBOM_BYTES },
    (_req, body, done) => {
      if (Buffer.byteLength(body as string, 'utf8') > MAX_SBOM_BYTES) {
        return done(new SbomValidationError('sbom.size.exceeded', 'body',
          'SBOM exceeds 10 MB limit'));
      }
      try {
        const doc = JSON.parse(body as string);
        return done(null, doc);
      } catch (e) {
        return done(new SbomValidationError('sbom.json.invalid', 'body',
          'SBOM is not valid JSON'));
      }
    }
  );

  app.post('/sbom/analyze', async (req) => {
    const doc = req.body as any;
    if (!doc || typeof doc !== 'object') {
      throw new SbomValidationError('sbom.body.invalid', 'body', 'body must be a CycloneDX JSON object');
    }
    if (doc.bomFormat !== 'CycloneDX') {
      throw new SbomValidationError('sbom.format.unsupported', 'bomFormat', 'only CycloneDX is supported');
    }
    const components = Array.isArray(doc.components) ? doc.components : [];
    if (components.length > MAX_COMPONENTS) {
      throw new SbomValidationError('sbom.components.exceeded', 'components',
        `component count ${components.length} exceeds ${MAX_COMPONENTS}`);
    }
    const deps = Array.isArray(doc.dependencies) ? doc.dependencies : [];
    let edgeCount = 0;
    for (const c of components) {
      assertName(c.name, `components[${components.indexOf(c)}].name`);
      assertPurl(c.purl,   `components[${components.indexOf(c)}].purl`);
    }
    for (const d of deps) {
      assertName(d.ref, `dependencies[${deps.indexOf(d)}].ref`);
      edgeCount += Array.isArray(d.dependsOn) ? d.dependsOn.length : 0;
      if (edgeCount > MAX_EDGES) {
        throw new SbomValidationError('sbom.edges.exceeded', 'dependencies',
          `edge count exceeds ${MAX_EDGES}`);
      }
    }
    // Depth check: BFS the dependency graph, max depth MAX_DEPTH
    const adj = new Map<string, string[]>();
    for (const d of deps) {
      adj.set(d.ref, Array.isArray(d.dependsOn) ? d.dependsOn : []);
    }
    const seen = new Set<string>();
    const queue: Array<[string, number]> = components.map(c => [c['bom-ref'] ?? c.purl, 1]);
    while (queue.length) {
      const [node, depth] = queue.shift()!;
      if (depth > MAX_DEPTH) {
        throw new SbomValidationError('sbom.depth.exceeded', 'dependencies',
          `dependency depth exceeds ${MAX_DEPTH}`);
      }
      if (seen.has(node)) continue;
      seen.add(node);
      for (const child of adj.get(node) ?? []) queue.push([child, depth + 1]);
    }
    return { ok: true, components: components.length, edges: edgeCount };
  });
});
```

The middleware **never echoes the offending value** in the error response — only the field path and a stable error code.

### 3.2 Per-tenant rate limiting

**File:** `backend/services/security/src/middleware/rate-limit.ts`

```typescript
// SPDX-License-Identifier: Apache-2.0
import type { FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';
import { createClient } from 'redis';

export type Bucket = 'sbom' | 'vuln' | 'risk';
interface Limit { capacity: number; refillPerSec: number; }

const LIMITS: Record<Bucket, Limit> = {
  sbom: { capacity: 10,   refillPerSec: 10/60  },  // 10 SBOM/min
  vuln: { capacity: 100,  refillPerSec: 100/60 },  // 100 vulns/min
  risk: { capacity: 60,   refillPerSec: 60/60  },  // 60 risk-calc/min
};

// Atomic token-bucket Lua: returns remaining tokens after this request.
// KEYS[1] = bucket key, ARGV = capacity, refillPerSec, nowMs
const LUA = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1]) or capacity
local ts = tonumber(data[2]) or now
local delta = (now - ts) / 1000.0
tokens = math.min(capacity, tokens + delta * refill)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', key, 60000)
return {allowed, math.floor(tokens)}`;

export const rateLimitMiddleware: FastifyPluginAsync<{ bucket: Bucket }> = fp(
  async (app, opts) => {
    const redis = createClient({ url: process.env.REDIS_URL });
    await redis.connect();
    const limit = LIMITS[opts.bucket];

    app.addHook('preHandler', async (req, reply) => {
      const tenantId = (req as any).tenantId;
      if (!tenantId) return; // auth middleware should have set this
      const key = `ratelimit:${tenantId}:${opts.bucket}`;
      const [allowed, remaining] = (await redis.eval(
        LUA, { keys: [key], arguments: [String(limit.capacity), String(limit.refillPerSec), String(Date.now())] }
      )) as [number, number];
      reply.header('X-RateLimit-Limit', String(limit.capacity));
      reply.header('X-RateLimit-Remaining', String(remaining));
      if (!allowed) {
        reply.header('Retry-After', '60');
        return reply.code(429).send({
          error: 'rate_limited',
          bucket: opts.bucket,
          trace_id: req.id,
        });
      }
    });
  }
);
```

Wiring (in `security-service/src/server.ts`):

```typescript
import { rateLimitMiddleware } from './middleware/rate-limit.js';

app.register(rateLimitMiddleware, { bucket: 'sbom' });
app.register(rateLimitMiddleware, { bucket: 'vuln' });
app.register(rateLimitMiddleware, { bucket: 'risk' });
```

### 3.3 Sandboxed Syft execution

**File:** `infra/sandbox/sbom-scanner/pod.yaml`

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sbom-scanner
  namespace: security
  labels:
    app: sbom-scanner
    security.aicc/sandbox: "true"
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10000
    runAsGroup: 10000
    fsGroup: 10000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: scanner
      # Pinned by digest; rotated via PR; verified at startup by an initContainer (see § 3.4).
      image: anchore/syft@sha256:REPLACE_WITH_PINNED_DIGEST
      imagePullPolicy: IfNotPresent
      command: ["/syft", "server", "--listen", "0.0.0.0:4954", "--token", "from-vault"]
      resources:
        requests: { cpu: 500m, memory: 1Gi }
        limits:   { cpu: 2,    memory: 4Gi }
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: syft-cache
          mountPath: /root/.cache/syft
        - name: work
          mountPath: /work
          readOnly: true
        - name: tmp
          mountPath: /tmp
      livenessProbe:
        httpGet: { path: /healthz, port: 4954 }
        initialDelaySeconds: 5
        periodSeconds: 10
  initContainers:
    - name: cosign-verify
      image: sigstore/cosign:v2.2.4
      command: ["/bin/sh", "-c"]
      args:
        - |
          cosign verify --keyless \
            --certificate-identity-regexp 'https://github.com/anchore/syft' \
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
            anchore/syft@${SYFT_DIGEST}
      env:
        - name: SYFT_DIGEST
          value: sha256:REPLACE_WITH_PINNED_DIGEST
      resources:
        requests: { cpu: 50m, memory: 64Mi }
        limits:   { cpu: 100m, memory: 128Mi }
  volumes:
    - name: syft-cache
      emptyDir: { sizeLimit: 1Gi }
    - name: work
      persistentVolumeClaim: { claimName: scanner-input-ro }
    - name: tmp
      emptyDir: { sizeLimit: 256Mi }
```

**NetworkPolicy — deny all egress:**

```yaml
# infra/sandbox/sbom-scanner/netpol.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sbom-scanner-deny-egress
  namespace: security
spec:
  podSelector:
    matchLabels:
      app: sbom-scanner
  policyTypes: ["Egress"]
  egress:
    # DNS to cluster CoreDNS only
    - to:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
    # Private registry mirror (DNS name pinned; resolved once by egress proxy)
    - to:
        - podSelector: { matchLabels: { app: egress-proxy } }
      ports: [{ port: 443, protocol: TCP }]
```

**AppArmor profile** (`/etc/apparmor.d/sbom-scanner`):

```
#include <tunables/global>
profile sbom-scanner flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  deny capability dac_override,
  deny capability dac_read_search,
  deny network inet stream,
  deny network inet6 stream,
  file,                                  # allow all file ops; we narrow via mounts
  deny /root/.ssh/** rw,
  deny /root/.aws/** rw,
  deny /root/.kube/** rw,
  deny /proc/*/environ r,
}
```

**Coordination request to SBOMPipelineAgent:** apply this Pod spec + NetworkPolicy + AppArmor profile in S2.1.

### 3.4 Cosign signature verification at startup

The initContainer in § 3.3 already does the verify. The startup script (for the Syft `trivy server` mode) is a Bash hook:

```bash
#!/usr/bin/env bash
# /opt/aicc/sbom-scanner/verify-image.sh
set -euo pipefail

IMAGE="anchore/syft@${SYFT_DIGEST}"
ALLOWED_IDENTITY_RE='https://github.com/anchore/syft'
ALLOWED_OIDC_ISSUER='https://token.actions.githubusercontent.com'

cosign verify --keyless \
  --certificate-identity-regexp "${ALLOWED_IDENTITY_RE}" \
  --certificate-oidc-issuer "${ALLOWED_OIDC_ISSUER}" \
  "${IMAGE}"

echo "[ok] cosign verification passed for ${IMAGE}"
```

The script is called by the `cosign-verify` initContainer. If verification fails, the pod is `CrashLoopBackOff` and the security-service pod that depends on it never reaches `Ready`. A Prometheus alert fires on `kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"}`.

### 3.5 CVE feed JSON-Schema validation

**File:** `backend/services/vuln-intel/src/feed-validator.ts` (TypeScript — same shape used by the Python services via a generated Python port)

```typescript
// SPDX-License-Identifier: Apache-2.0
import Ajv, { ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';

const NVD_CVE_SCHEMA = {
  type: 'object',
  required: ['cve'],
  properties: {
    cve: {
      type: 'object',
      required: ['id', 'metrics', 'descriptions'],
      properties: {
        id: { type: 'string', pattern: '^CVE-\\d{4}-\\d{4,7}$' },
        metrics: {
          type: 'object',
          properties: {
            cvssMetricV31: { type: 'array', maxItems: 8 },
            cvssMetricV30: { type: 'array', maxItems: 8 },
          },
        },
        descriptions: {
          type: 'array',
          items: {
            type: 'object',
            required: ['lang', 'value'],
            properties: {
              lang: { type: 'string', enum: ['en', 'es', 'fr', 'de', 'ja', 'zh'] },
              value: { type: 'string', maxLength: 16_000 },
            },
          },
        },
      },
    },
  },
};

const GHSA_SCHEMA = {
  type: 'object',
  required: ['ghsa_id', 'severity', 'cvss'],
  properties: {
    ghsa_id: { type: 'string', pattern: '^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$' },
    severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
    cvss: {
      type: 'object',
      properties: {
        score: { type: 'number', minimum: 0, maximum: 10 },
        vector_string: { type: 'string', pattern: '^CVSS:3\\.[01]/.+' },
      },
    },
  },
};

const OSV_SCHEMA = {
  type: 'object',
  required: ['id', 'summary', 'affected'],
  properties: {
    id: { type: 'string', minLength: 1, maxLength: 256 },
    summary: { type: 'string', maxLength: 8_000 },
    affected: { type: 'array', maxItems: 50_000 },
  },
};

export class FeedValidator {
  private validators = new Map<string, ValidateFunction>();
  private ajv = new Ajv({ allErrors: true, removeAdditional: 'failing' });
  constructor() { addFormats(this.ajv); this.validators.set('nvd', this.ajv.compile(NVD_CVE_SCHEMA)); }
  validateNVD(record: unknown): { ok: true } | { ok: false; errors: string[] } {
    return this.check('nvd', record);
  }
  // validateGHSA, validateOSV similar
  private check(name: string, record: unknown) {
    const fn = this.validators.get(name)!;
    if (fn(record)) return { ok: true as const };
    return { ok: false as const, errors: (fn.errors ?? []).map(e => `${e.instancePath} ${e.message}`) };
  }
}

export function rangeCheckCvss(score: number): boolean {
  return Number.isFinite(score) && score >= 0 && score <= 10;
}
export function rangeCheckEpss(score: number): boolean {
  return Number.isFinite(score) && score >= 0 && score <= 1;
}
```

**Cross-source consensus gate** — a CVE is only eligible for HIGH/CRITICAL scoring if it appears in ≥2 of {NVD, GHSA, OSV}:

```typescript
// In the vulnerability engine:
function isHighConfidence(cveId: string, present: { nvd: boolean; ghsa: boolean; osv: boolean }): boolean {
  const sourcesPresent = [present.nvd, present.ghsa, present.osv].filter(Boolean).length;
  return sourcesPresent >= 2;
}
```

### 3.6 Audit log for risk-score calculations

**File:** `backend/services/security/src/middleware/risk-score-audit.ts`

```typescript
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { Pool } from 'pg';

const pg = new Pool({ connectionString: process.env.AUDIT_DB_URL });

export interface RiskScoreInput {
  tenantId: string;
  assetId: string;
  sbomFingerprint: string;       // sha256 of the SBOM bytes
  cveSnapshotId: string;         // versioned id of the CVE snapshot used
  policyId: string;              // versioned id of the policy used
  topContributors: Array<{ cveId: string; weight: number }>;  // top 5
  score: number;                 // 0..100
}

export async function recordRiskScoreCalculation(
  input: RiskScoreInput,
  actor: { id: string; type: 'user'|'service'|'agent'; ip?: string }
): Promise<void> {
  const prev = await pg.query<{ hash: string }>(
    'SELECT hash FROM audit_log WHERE tenant_id=$1 ORDER BY id DESC LIMIT 1',
    [input.tenantId]
  );
  const prevHash = prev.rows[0]?.hash ?? '0'.repeat(64);

  const record = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    tenant_id: input.tenantId,
    actor,
    action: 'security.risk_score.calculated',
    target: { type: 'asset', id: input.assetId },
    inputs: {
      sbom_fingerprint: input.sbomFingerprint,
      cve_snapshot_id: input.cveSnapshotId,
      policy_id: input.policyId,
    },
    output: {
      score: input.score,
      top_contributors: input.topContributors,
    },
    prev_hash: prevHash,
  };
  // Canonicalize via sorted keys to be deterministic across processes
  const canonical = JSON.stringify(record, Object.keys(record).sort());
  const hash = crypto.createHash('sha256').update(prevHash + canonical).digest('hex');
  await pg.query(
    `INSERT INTO audit_log
       (id, ts, tenant_id, actor, action, target, inputs, output, prev_hash, hash, record)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [record.id, record.ts, record.tenantId, record.actor, record.action,
     record.target, record.inputs, record.output, prevHash, hash, canonical]
  );
}
```

The audit table schema:

```sql
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant_id   UUID NOT NULL,
  actor       JSONB NOT NULL,
  action      TEXT NOT NULL,
  target      JSONB NOT NULL,
  inputs      JSONB NOT NULL,
  output      JSONB NOT NULL,
  prev_hash   BYTEA NOT NULL,
  hash        BYTEA NOT NULL,
  record      JSONB NOT NULL
);
CREATE INDEX audit_log_tenant_ts_idx ON audit_log (tenant_id, ts DESC);
```

**Retention** (per ComplianceOfficer alignment):
- 0–90 days: hot, queryable in Postgres.
- 90 d – 1 y: warm, daily export to Parquet in object storage, queryable via Athena/Trino.
- 1 y – 7 y: cold, archive in object storage with object-lock (WORM).

## 4. Risks

| Risk | Mitigation | Status |
|------|------------|--------|
| `cosign` keyless verification depends on Rekor transparency log availability; if Rekor is down, pod startup fails | Cache the most recent Rekor checkpoint for 24h; on Rekor 5xx, allow startup with a 1h SLO breach alert | Open (S2.7) |
| Egress proxy is a SPOF for the SBOM pipeline; one bad config blocks all scans | HA proxy (≥2 replicas); per-tenant circuit breaker; if proxy down, fail-closed with clear error to the user | Open |
| PURL regex strictness: rejecting valid PURLs is a customer-facing issue | CI test corpus of 10k+ real PURLs from npm, PyPI, Maven, Go, Cargo, RubyGems, NuGet; fuzz tests with PURL spec test vectors | Open |
| Audit log chain growth: with 60 risk-calc/min/tenant, the chain is large | Sample and hash hot data; object storage for cold; quarterly retention rotation | Open |
| Cosign image digests must be rotated; a too-rapid rotation breaks all pods | Canary deploy: 1 pod new digest, watch for 30 min, then roll; old digest valid 7 days | Open |
| Sandbox restricts the scanner; some Syft features (e.g., live `registry:auth` logins) need explicit exception | Per-tenant registry-credential volume mount with NetworkPolicy exception; documented in onboarding | Open |

## 5. Next actions

1. **SBOMPipelineAgent (S2.1)** — adopt the Pod spec in § 3.3, the cosign verify script in § 3.4, and the NetworkPolicy in § 3.3. Coordinate with SREEngineer for the AppArmor profile rollout.
2. **VulnerabilityIntelligenceAgent (S2.2, S2.3)** — implement `FeedValidator` from § 3.5 in the Python service (port the same AJV schema using `jsonschema`); add the cross-source consensus gate before any HIGH/CRITICAL scoring.
3. **FullstackEngineer (S2.4, S2.5)** — wire `sbomInputMiddleware` and `rateLimitMiddleware` into the security-service router; add the audit log table migration; expose the `POST /sbom/analyze` endpoint with these middlewares applied.
4. **ComplianceOfficer (S2.9)** — confirm the `audit_log` table format matches the CIS/NIST evidence requirements; align on the hash-chain seed initialization (use the tenant creation timestamp, not `0...0`).
5. **SREEngineer (S2.7)** — emit metrics: `cosign_verify_duration_seconds{result}`, `sbom_validation_errors_total{code}`, `rate_limit_rejections_total{bucket, tenant}`, `risk_score_audit_chain_verified{ok}`.
6. **SecurityArchitect (me, ongoing)** — review and approve the integration tests in `docs/security/s2-test-plan.md` before S2.11.

---

*End of S2 Security Mitigations — security-service Extensions.*