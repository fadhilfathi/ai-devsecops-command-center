# NIST 800-53 — Detailed Control Narratives

This directory is reserved for **per-control** (or per-control-family)
implementation details beyond the master mapping in
[`../nist-800-53.md`](../nist-800-53.md).

Contents may include:

- Per-control assessment procedures.
- Per-control evidence-record samples.
- Compensating-control analyses.
- Cross-walk to non-listed baselines (e.g., NIST 800-171, CMMC).

## When to add a file here

When a single NIST control is complex enough to warrant a multi-page
narrative (e.g., a full AU-9 audit storage design, or a detailed
SC-12 cryptographic key management procedure), add it here.
Otherwise, keep the control in the master mapping table.

## Per-family subdirectories

When a family accumulates several narrative documents, organize them
into per-family subdirectories (e.g., `AC/`, `AU/`, `SC/`).
