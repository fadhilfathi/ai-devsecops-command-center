/**
 * Security models — barrel re-export.
 *
 * Canonical home: `backend/models/security/`
 * Re-exported from: `backend/packages/shared/src/security/` (consumed by
 * the security-service and any other TS service that handles security data)
 */
export * from './sbom.model.js';
export * from './vulnerability.model.js';
export * from './dependency-graph.model.js';
export * from './risk-score.model.js';
