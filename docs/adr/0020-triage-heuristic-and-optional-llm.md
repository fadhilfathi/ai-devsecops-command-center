# 0020 — Triage: deterministic heuristic default, optional clamp-limited LLM refinement

Status: accepted
Date: 2026-09-27

## Context

`agent-service`'s `TriageAgent` (`backend/services/agent/src/agents/
registry.ts`) shipped in Sprint 1 as a placeholder: it counted findings
by severity and picked `open_incident`/`log_only`, with a comment
saying an LLM was coming "in Sprint 2". S9-4 replaces it. CLAUDE.md's
zero-cost rule requires the platform to fully work with no API key, so
any LLM use must be opt-in with a heuristic fallback — the same pattern
`agents/roles/security/vuln-intel/src/vuln_intel/llm.py` already uses
for exploit scoring (env-gated, OpenAI-compatible endpoint, strict
schema validation on the response, always falls back on any failure).

## Decision

- `backend/services/agent/src/agents/triage.ts` exports a pure,
  synchronous `heuristicTriage()` — the default and only requirement.
  It validates input with Zod (`FindingSchema`, unknown fields
  ignored), scores each finding (base score by severity; + KEV; +
  EPSS ≥ 0.5; + internet exposure; + asset criticality; − no fix
  available softens urgency only, never blocks an incident), maps the
  worst finding's score to a priority band (P1 ≥ 80, P2 ≥ 60, P3 ≥ 35,
  else P4), and a priority to a decision (P1/P2 → `open_incident`, P3
  → `create_ticket`, P4 → `log_only`). Every contributing factor is
  pushed onto a human-readable `rationale` string array.
- LLM refinement (`refineWithLlm`) is opt-in via
  `AICC_AGENT_LLM_ENABLED=true` + `AICC_AGENT_LLM_API_KEY` (also
  `AICC_AGENT_LLM_BASE_URL`, default `https://api.openai.com/v1`;
  `AICC_AGENT_LLM_MODEL`; `AICC_AGENT_LLM_TIMEOUT_MS`, default
  10000). It posts to `<base>/chat/completions` with
  `response_format: {type: 'json_object'}` using native `fetch`
  (`AbortController` for the timeout) — no new dependency.
- **Injection surface**: only structured fields
  (`severity`/`cveId`/`kev`/`epss`/`cvss`/`fixAvailable`/
  `assetCriticality`/`exposure`) ever reach the prompt; free-text
  fields are never forwarded, and findings are capped at 50. The
  system prompt is a static string constant, mirroring `vuln-intel`'s
  "CVE id and CVSS vector are user-turn only" rule.
- **Clamp ±1**: the LLM's proposed priority is only accepted if it is
  within one level of the heuristic's priority (`P1..P4` treated as an
  ordinal). A larger jump is discarded and the heuristic result is
  returned unchanged. This bounds how much a single opaque model call
  can move triage away from the explainable default.
- **Fail closed to the heuristic**: disabled, no key, non-2xx, timeout,
  invalid JSON, Zod schema mismatch, or a clamp violation — all of
  these return the heuristic result with `engine: 'heuristic'` and a
  `logger.warn` (never logging the API key or the full prompt). Only
  a fully valid, in-clamp response sets `engine: 'llm'`.
- Zero-cost path: any OpenAI-compatible endpoint works, including a
  local Ollama/llama.cpp server — documented in
  `docs/quick-start.md`'s "Optional: LLM-assisted triage" section.

## Consequences

- `TriageAgent.run` now calls `triage()` and returns its result
  directly; the old severity-count placeholder and its "Sprint 2"
  comment are gone.
- `RemediationAgent` is untouched — still the Sprint-1 placeholder,
  tracked as the next one in `ROADMAP.md`.
- New tests: `src/agents/triage.test.ts` (heuristic table, LLM success/
  clamp-violation/timeout/invalid-JSON/non-2xx/schema-mismatch/
  disabled/no-key paths, and a log-call assertion that the API key
  never appears in a logged value) plus a route-level test in
  `src/app.test.ts`.
