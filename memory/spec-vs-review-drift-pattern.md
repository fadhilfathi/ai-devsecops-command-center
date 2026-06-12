---
name: spec-vs-review-drift-pattern
description: Pattern observed in Sprint 2 closeout — agents emit code on a round-N spec, the spec gets amended at round N+1, and the emitted code drifts silently. Two catches so far.
type: feedback
---

**Pattern:** when the S2.7 / S2.9 / S2.10 specs are amended between rounds (round 5 → round 6 closure on 2026-06-12), the agents' emitted code may stay on the previous round's values. The spec docs (metrics-spec.md, slos-security-stack.md, wire-format JSON Schemas) are the source of truth, but the agent's runtime code is the actual emitter. If the runtime code is not re-verified against the new spec, the runtime silently emits labels/values that no alert rule, SLO, or downstream consumer recognizes.

**Two catches in Sprint 2 closeout:**

1. **SREEngineer's own reviews** (caught 2026-06-12): two earlier S2.7 reviews endorsed `tenant_id_hash` as a label, which violated the LOCKED spec §5.1. Security-service :4003 per-service total was ~109,400 series; with `tenant_id_hash` dropped, drops to ~560 series (1,950× reduction). The spec is the source of truth; the runtime is correctly spec-compliant; the earlier reviews were wrong. The ~97k series number was based on the pre-refactor design. (SRE acknowledged in turn 6, updated `metrics-spec.md` v1.0.4.)

2. **SBOM agent's `sbom_size_bucket()`** (caught 2026-06-12, Lead-applied follow-up commit `a20f59a`): was on the round-5 scheme (small/medium/large/xlarge/xxlarge with 100/1k/10k/50k thresholds) while the S2.7 spec D7 LOCKED is xs/small/medium/large/xlarge with 10/100/1k/5k thresholds (xxlarge RETIRED, xs ADDED). The D7 amendment was made on 2026-06-12 round 6 closure, AFTER the SBOM agent's hotfix commit. The agent's smoke tests (50→small, 100→medium, 9999→large, 49999→xlarge, 50000→xxlarge) were validating the WRONG scheme. Lead fix: `agents/roles/security/sbom-generator/src/sbom_generator/metrics.py` updated to D7 scheme.

**Pattern fix (filed as part of ADR 0009, cardinality discipline):**

1. **Cross-metric lock** — any change to a label vocabulary in the S2.7 spec must trigger a `git diff` check across all emission sites BEFORE the spec amendment closes. For `sbom_size_bucket`, the 3 sites are: sbom-generator `metrics.py`, dependency-intel histogram labels, alert-rules.yml queries.

2. **Spec-ratified docstring** — every public function in the agent repos that emits a metric label must include the spec section number in its docstring (e.g., `"""...per metrics-spec.md §3.1 D7 LOCKED..."""`). This makes drift visible at code review time.

3. **Lead follow-up commit pattern** — when an agent's emitted code drifts from the spec, the Lead applies the fix directly (don't delegate back to the agent). The Lead's perspective is spec-first; the agent's perspective is implementation-first. Spec wins.

4. **Round-6 closeout audit** — the Sprint 2 round-6 closure had 5 spec amendments (D6 tenant_tier APPROVED, D7 5-bucket LOCKED, §3.8.4 merge, §3.10.7 delete, §3.11 new gauge). Each amendment should have triggered a Lead audit of the 3-5 affected emission sites. The SBOM agent's 5-bucket was missed.

**Sprint 2.1 follow-up:** tighten the cross-metric lock + add the spec-ratified docstring requirement to the Sprint 2.1 review checklist. Sprint 2.1 process gate: any new metric label added to a public function must include a `Spec: metrics-spec.md §X.Y` docstring line.
