---
status: accepted
date: 2026-06-12
deciders: GitOpsManager
---

# 0005 — Record architecture decisions

## Context

We are starting a new system. We will face many decisions that have lasting
impact on how the system is shaped. Without a record, we will re-litigate
the same questions every time someone new joins, and we will lose the
*why* of past choices.

## Decision

We will use **Architecture Decision Records (ADRs)** in the lightweight
Michael Nygard format.

- Every significant decision gets a numbered file in `docs/adr/`.
- Filenames are `NNNN-kebab-title.md`, e.g. `0007-event-versioning.md`.
- The status is one of: `proposed`, `accepted`, `rejected`, `superseded`,
  `deprecated`.
- The format is:

```markdown
---
status: <status>
date: <YYYY-MM-DD>
deciders: <who>
supersedes: <optional ADR number>
---

# <number> — <title>

## Context
What is the issue? What forces are at play?

## Decision
What did we choose?

## Consequences
What becomes easier? What becomes harder?

## Alternatives considered
What else did we look at, and why didn't we pick it?
```

- ADRs are **immutable** once `accepted`. A new decision that reverses an
  ADR adds a new ADR that **supersedes** the old one (and updates the old
  one's status).
- ADRs are reviewed in PRs, like any other change. Approvals follow
  CODEOWNERS.

## Consequences

- **Easier**: on-boarding new contributors; reasoning about legacy
  decisions; defending choices in audits.
- **Harder**: requires discipline to keep the log up to date; an "obvious"
  decision can feel like overhead. We commit anyway.

## Alternatives considered

- **ADRs in the wiki**: rejected. Wikis drift, lack code review, and are
  not versioned with the code they describe.
- **ADRs in the design doc only**: rejected. The architecture doc becomes a
  graveyard of decisions nobody reads.
- **No record**: rejected. We have already lost too much institutional
  knowledge to "we used to do X because…".
