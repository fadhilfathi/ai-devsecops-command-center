---
name: Coordinating with parallel teammates
description: Lessons learned from the Sprint 1 parallel-work coordination experience
type: feedback
---

# Coordinating with parallel teammates

> When multiple agents work in the same repo at the same time, you will
> see overlap and conflict. This memo records what worked in Sprint 1.

## What happened

In Sprint 1, I was assigned the **Repository Structure & Initialization**
and **Documentation** tasks. When I started, other agents had already
been working for some time and had created:

- Full backend service code (FullstackEngineer) with the
  `@aicc/<svc>` naming and `backend/packages/shared/` path.
- A complete observability stack (SREEngineer) at
  `infra/observability/{prometheus,otel-collector,alertmanager,grafana,logs}/`
  and `docs/observability/`.
- A full frontend (UIUXEngineer) with all 8 screens implemented.
- Canonical architecture docs and ADRs 0001-0004 (PlatformArchitect).
- Canonical auth and GitHub integration designs (SecurityArchitect).
- Compliance mapping (ComplianceOfficer).

My initial work overlapped with all of these in different ways.

## What I did

1. **Sent a coordination message to the Lead** listing the overlaps I
   had found and the cleanup I was about to do. This is the single most
   important step — it lets the Lead and the team course-correct
   *before* I waste effort on something that's already done.

2. **Sent targeted messages to the teammates whose work I was
   touching** (PA, SRE, FullstackEngineer, UIUXEngineer) so they knew
   I wasn't duplicating their work and could flag any concern.

3. **Renumbered my ADRs** to 0005-0007 (after PA's 0001-0004) and
   deleted the 6 ADRs that overlapped with PA's domain.

4. **Deleted my duplicate files** in `backend/shared/` (wrong path),
   `infra/observability/` (SRE has the real ones), and
   `backend/tests/` (tests are per-service now).

5. **Updated cross-references** in the architecture docs and READMEs
   to point to the canonical locations.

6. **Updated naming** from `@cc/...` to `@aicc/...` everywhere it
   appeared.

7. **Made my docs explicitly draft** (added a "Status: Sprint 1 draft"
   note) so the canonical authors can replace them.

8. **Wrote a memory note** (`memory/gitops-manager-sprint-1.md`)
   describing what I did and the conventions I observed.

## Lessons

- **Read the repo before you start.** Use `Glob` and `Grep` aggressively
  to see what exists. Don't assume a fresh-empty repo.
- **Read the `memory/` folder.** Other agents are leaving notes there.
  The Lead and PA in particular used it to publish their decisions.
- **Don't fight other agents' work.** Defer. If your work is genuinely
  better, raise it as a *follow-up* PR, not a parallel one.
- **Send the coordination message early.** A 2-paragraph message at the
  start of your work is worth more than a perfect merge at the end.
- **Be explicit about ownership.** "I will own X, Y, Z; I will defer to
  A on A, B, C" prevents ambiguity.
- **Numbered ADRs are a coordination surface.** Pause and check
  `docs/adr/` before publishing a new one.
- **Package names and folder paths are coordination surfaces too.**
  Read at least one other package's `package.json` before assuming the
  conventions.
- **CI is the ground truth.** If the existing CI passes, don't change
  it; if it fails, fix it (or document why you're not).
- **Trust the memory index.** If `memory/MEMORY.md` lists a memo for
  your area, read it before writing your own.

## What I would do differently next time

- Check the `memory/` folder **first**, before reading any code.
- Send a single short coordination message to **all** teammates at the
  start, not just the ones I think I'm overlapping with.
- Use `git ls-files` early to understand what's already committed.
- Set up a personal scratchpad (`memory/<my-role>-scratch.md`) at the
  start so I have somewhere to track my decisions.
