# 0016 — Cluster credential encryption at rest

Status: accepted
Date: 2026-09-23

## Context

ADR-0010 flagged that the kubernetes-service `clusters` table stores
onboarded-cluster `token`/`ca_bundle` values in plain columns as a
follow-up. Sprint 6 closes that gap.

## Decision

- **AES-256-GCM envelope encryption**, implemented with `node:crypto`
  only (no new dependency) in `@aicc/shared/crypto`:
  `encryptSecret`/`decryptSecret`/`parseKeyring`/`createCipherKeyring`/
  `generateKey`.
- **Ciphertext format**: `v1.<keyId>.<iv-b64>.<tag-b64>.<ct-b64>` — a
  random 12-byte IV per call, the key id passed as AAD (so a ciphertext
  produced under one key id cannot be replayed as belonging to
  another), and the GCM auth tag detects tampering.
- **Keyring format**: `AICC_CREDENTIAL_KEYS=keyId:base64key[,keyId:base64key...]`.
  The first entry is the active key (used to encrypt); every entry is
  kept for decryption, which is the rotation procedure:
  1. Generate a new key (`node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`).
  2. Prepend `newKeyId:newKey` to `AICC_CREDENTIAL_KEYS`, **keep the old
     key entry present**, redeploy. New writes use the new (active) key;
     `reencryptCredentials` (see below) runs automatically on this boot
     and moves every row still under the old key onto the new one.
  3. Verify no rows remain under the old key id before touching the env
     var again — check the startup log line
     (`kubernetes-service: re-encrypted cluster credentials under the
active key`) settles at `reencrypted: 0` on a subsequent restart,
     or run `SELECT count(*) FROM clusters WHERE credential_key_id <>
'<newKeyId>' AND (token_enc IS NOT NULL OR ca_bundle_enc IS NOT
NULL)` and confirm it's `0`.
  4. Only once that count is `0`, remove the old key entry from
     `AICC_CREDENTIAL_KEYS` and redeploy. **Dropping the old key before
     verifying** would make any row still encrypted under it
     permanently undecryptable — the old key must stay in the keyring
     until every row has been moved off it.
- **kubernetes-service config** (`src/config.ts`, mirrors
  `loadServiceConfig`'s `AUTH_JWT_SECRET` handling): in production, a
  missing or malformed `AICC_CREDENTIAL_KEYS` refuses to boot. In dev,
  an unset/invalid value falls back to plaintext storage with a single
  logged warning, so existing dev flows and tests keep working with no
  setup.
- **Schema**: migration `002_cluster_credential_columns` adds
  `token_enc`, `ca_bundle_enc`, `credential_key_id` alongside the
  existing `token`/`ca_bundle` columns. `getConnection()` prefers the
  `_enc` columns (decrypting them) and falls back to the legacy plain
  columns when `_enc` is null. `create()` writes to the `_enc` columns
  when a keyring is configured, or the legacy plain columns otherwise
  (dev fallback). `list()`/`findById()` never select credential columns
  at all — unchanged from ADR-0010, and additionally the in-memory
  repository's `list()`/`findById()`/`create()` now strip the internal
  `_credentials` field before returning, closing a leak where those
  paths handed back the full stored record.
- **One-shot re-encryption of legacy plaintext**: `migrateCredentials(db,
keyring, logger)` in `src/db/migrations.ts`. Run at startup, after
  `migrate()`, only when a keyring is configured. It batches over rows
  with a non-null plaintext `token`/`ca_bundle`, encrypts them, writes
  the `_enc` columns and `credential_key_id`, and nulls the plaintext
  columns — idempotent, since a migrated row no longer matches the
  `WHERE token IS NOT NULL OR ca_bundle IS NOT NULL` filter.
- **Forced re-encryption on key rotation**: `reencryptCredentials(db,
keyring, logger)`, also in `src/db/migrations.ts`, runs at startup
  right after `migrateCredentials`. It batches over rows whose
  `credential_key_id` isn't the keyring's current active key id,
  decrypts (with whichever retained key the ciphertext names) and
  re-encrypts under the active key, and updates `credential_key_id` —
  idempotent for the same reason. This is what makes the rotation
  procedure above safe: the old key only needs to stay in the keyring
  until this pass has moved every row.
- **Credential substitution guard**: the Pg repository's `getConnection`
  refuses to serve a row where a keyring is configured, the `_enc`
  column is null, and the legacy plaintext column is non-null — that
  combination is never produced by any write path (encryption is
  synchronous on write, and `migrateCredentials` nulls the plaintext
  column in the same statement it sets `_enc`), so it can only mean the
  plaintext column was written out-of-band. It throws and logs a
  warning with the cluster id (never the value).
- **Plaintext read path**: `decryptSecret` is only ever called without
  `allowPlaintext` on the ciphertext (`_enc`) branch. The unencrypted
  legacy column is read as-is (no decryption call at all) and only
  when no keyring is configured — both the in-memory and Pg
  repositories branch on which column pair is populated rather than
  trying to decrypt a value that might be plaintext.
- **Dropping the plain columns is a later migration.** They stay for
  now so a keyring can be disabled again (or `migrateCredentials`
  hasn't run yet, e.g. a fresh `DATABASE_URL` swapped in) without data
  loss. Once every environment has run `migrateCredentials` at least
  once, a follow-up migration drops `token`/`ca_bundle`.
- **No KMS.** A hosted KMS (AWS KMS, GCP KMS, HashiCorp Vault) would
  manage key material and rotation without it ever living in an env
  var, but that requires a paid account or extra infrastructure this
  project doesn't run (zero-cost, local-first — see `CLAUDE.md`). The
  keyring env var is the local-first equivalent; swapping in a KMS
  later only touches `loadCredentialKeyring`.

## What this does NOT protect against

- **Process memory.** Decrypted tokens live as plain strings in memory
  for the lifetime of a request/cached client (`LiveProvider`'s client
  cache) — a memory dump or a debugger attached to the process exposes
  them, same as any in-process secret.
- **Logs.** Nothing in this change scrubs tokens from application logs;
  callers must continue to avoid logging `ClusterConnection` values.
  (Existing code doesn't log them today.)
- **A compromised kubernetes-service.** Whoever has `AICC_CREDENTIAL_KEYS`
  and DB access can decrypt every row — this defends the _data at
  rest_ (a DB backup, snapshot, or leaked dump), not a compromised
  running service.

## Consequences

- `AICC_CREDENTIAL_KEYS` is a new required production secret; `.env.example`
  documents its format and a generation command. Local/dev/CI keep
  working unset (plaintext, one warning).
- Adding a keyring to an existing deployment (DB already has plaintext
  rows) is zero-downtime: set the env var, redeploy, `migrateCredentials`
  runs automatically on the next boot.
- Amends ADR-0010's "credentials stored in plain columns" note — see
  this ADR for the resolution.
