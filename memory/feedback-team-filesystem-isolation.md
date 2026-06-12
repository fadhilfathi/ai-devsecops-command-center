---
name: Team filesystem isolation — return deliverables inline
description: CRITICAL — Lead cannot see files written by teammate agents; always return deliverable content (file lists, key snippets, diffs) inline in messages
type: feedback
---
# Team filesystem isolation — return deliverables inline

## The problem
When this agent (the Lead / orchestrator) spawns or coordinates with
teammate agents, **the Lead's Read/Glob tools cannot see the files that
teammate agents write to disk**. The teammate's working directory is
sandboxed from the Lead's filesystem view.

This is a hard invariant of the team execution model, not a bug. It
applies to:
- `Write`/`Edit` operations performed by teammates
- Files created by teammate shell commands
- Output of teammate test runs, builds, etc.

## What this means in practice
- **Never** tell the user "I wrote the file to <path>" without also
  showing the **content** of the file inline in the message
- For multi-file deliverables, return a table with file path + a
  short snippet of the most important changes
- For code reviews / PRs, paste the diff inline
- For test results, paste the output inline (or a summary + key lines)

## What this does NOT mean
- The user's filesystem CAN see the teammate's output (if it was
  written to a real path the user has access to). The Lead just
  can't see it through its own tools.
- This is a coordination constraint, not a security boundary. The
  user is the only true reviewer.

## When to apply
- Every status update from the Lead
- Every "ready for review" message
- Every closeout / handoff
- Sprint / ticket close messages
- Whenever a teammate says "done" — re-summarize their work with
  the actual content the user can verify

## Origin
Discovered during Sprint 2 closeout. The Lead had multiple teammates
write deliverables to disk and reported "X files created" without
inline content. The user couldn't see what was actually produced.
After a back-and-forth the user explicitly required inline content
in all handoff messages.
