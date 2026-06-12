/**
 * Shared security package — barrel re-export.
 *
 * Imports the canonical models from `backend/models/security/` and the
 * event-bus topic constants from `./topics.ts`. Services consume this
 * via `@aicc/shared/security` (or relative import, per build setup).
 */
export * from './models.js';
export * from './topics.js';
