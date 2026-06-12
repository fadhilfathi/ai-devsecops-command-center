/**
 * Shared security contracts — re-exported from the canonical models directory.
 *
 * This is the package-surface import path used by services and the agent
 * runtime. The canonical source-of-truth files live at:
 *   `backend/models/security/*.ts`
 *
 * Python agents must NOT import from here — they mirror the same shapes
 * in Pydantic at `agents/sbom_pipeline/models.py` and
 * `agents/vuln_intel/models.py` (or the equivalent per-agent path).
 */
export * from '../../../../models/security/index.js';
