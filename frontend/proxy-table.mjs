// Single source of truth for the browser-facing `/api/*` -> backend service
// proxy map. One entry per top-level resource (not per service), because a
// single service can own several browser-facing resources (e.g.
// security-service owns /api/assets, /api/scans, /api/findings, /api/sboms,
// plus a handful of unversioned action routes).
//
// Consumed by:
//   - vite.config.ts        (dev server proxy)
//   - scripts/gen-nginx.mjs (generates nginx.conf for the production image)
//
// Plain ESM/JS (not TS) so it can be `node`-executed directly by the
// generator without a TS runtime — no new devDependency needed.
//
// `browserPath` has no trailing slash. `upstreamPath` is the path the
// backend route is actually mounted under (verified against
// `backend/services/*/src/routes/*.ts` — several services mount routes
// unversioned, e.g. compliance's POA&M routes and security's pipeline
// proxy routes, so this is NOT a uniform `/v1/<name>` rewrite).
export const PROXY_TABLE = [
  // ---- security-service (3003) ----
  {
    browserPath: '/api/assets',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/assets',
  },
  {
    browserPath: '/api/scans',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/scans',
  },
  {
    browserPath: '/api/findings',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/findings',
  },
  {
    browserPath: '/api/sboms',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/sboms',
  },
  {
    browserPath: '/api/sbom/components',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/sbom/components',
  },
  {
    browserPath: '/api/vulnerabilities',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/v1/vulnerabilities',
  },
  {
    browserPath: '/api/security/dashboard',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/security/dashboard',
  },
  {
    browserPath: '/api/security/score',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/security/score',
  },
  {
    browserPath: '/api/security/vuln-timeline',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/security/vuln-timeline',
  },
  {
    browserPath: '/api/security/risk-heatmap',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/security/risk-heatmap',
  },
  {
    browserPath: '/api/security/graph',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/security/graph',
  },
  {
    browserPath: '/api/risk/calculate',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/risk/calculate',
  },
  {
    browserPath: '/api/sbom/generate',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/sbom/generate',
  },
  {
    browserPath: '/api/sbom/analyze',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/sbom/analyze',
  },
  {
    browserPath: '/api/vulnerabilities/ingest',
    port: 3003,
    container: 'security-service',
    upstreamPath: '/vulnerabilities/ingest',
  },

  // ---- incident-service (3004) ----
  {
    browserPath: '/api/incidents',
    port: 3004,
    container: 'incident-service',
    upstreamPath: '/v1/incidents',
  },

  // ---- compliance-service (3005) ----
  {
    browserPath: '/api/controls',
    port: 3005,
    container: 'compliance-service',
    upstreamPath: '/v1/controls',
  },
  {
    browserPath: '/api/evidence',
    port: 3005,
    container: 'compliance-service',
    upstreamPath: '/v1/evidence',
  },
  {
    browserPath: '/api/frameworks',
    port: 3005,
    container: 'compliance-service',
    upstreamPath: '/v1/frameworks',
  },
  // poam.ts mounts unversioned (no /v1 prefix) despite its own comments.
  { browserPath: '/api/poam', port: 3005, container: 'compliance-service', upstreamPath: '/poam' },

  // ---- integration-service (3006) ----
  {
    browserPath: '/api/integrations',
    port: 3006,
    container: 'integration-service',
    upstreamPath: '/v1/integrations',
  },
  {
    browserPath: '/api/providers',
    port: 3006,
    container: 'integration-service',
    upstreamPath: '/v1/providers',
  },

  // ---- agent-service (3002) ----
  {
    browserPath: '/api/agents',
    port: 3002,
    container: 'agent-service',
    upstreamPath: '/v1/agents',
  },

  // ---- auth-service (3001) ----
  { browserPath: '/api/auth', port: 3001, container: 'auth-service', upstreamPath: '/v1/auth' },
  { browserPath: '/api/users', port: 3001, container: 'auth-service', upstreamPath: '/v1/users' },

  // ---- kubernetes-service (4006) — flattened resource names; no
  // `/kubernetes/` segment in the browser path.
  ...[
    'clusters',
    'namespaces',
    'workloads',
    'pods',
    'services',
    'ingresses',
    'deployments',
    'statefulsets',
    'daemonsets',
    'network-policies',
  ].map((resource) => ({
    browserPath: `/api/${resource}`,
    port: 4006,
    container: 'kubernetes-service',
    upstreamPath: `/v1/kubernetes/${resource}`,
  })),

  // ---- k8s-health-service (4007) ----
  {
    browserPath: '/api/health',
    port: 4007,
    container: 'k8s-health-service',
    upstreamPath: '/v1/health',
  },

  // ---- runtime-security-service (4008) ----
  {
    browserPath: '/api/runtime-security',
    port: 4008,
    container: 'runtime-security-service',
    upstreamPath: '/v1/runtime-security',
  },

  // ---- inventory-service (4009) ----
  {
    browserPath: '/api/inventory',
    port: 4009,
    container: 'inventory-service',
    upstreamPath: '/v1/inventory',
  },

  // ---- cost-intelligence-service (4010) ----
  {
    browserPath: '/api/cost',
    port: 4010,
    container: 'cost-intelligence-service',
    upstreamPath: '/v1/cost',
  },

  // ---- topology-service (4011) ----
  {
    browserPath: '/api/topology',
    port: 4011,
    container: 'topology-service',
    upstreamPath: '/v1/topology',
  },

  // ---- reporting-service (4012) ----
  {
    browserPath: '/api/reports',
    port: 4012,
    container: 'reporting-service',
    upstreamPath: '/v1/reports',
  },
];
