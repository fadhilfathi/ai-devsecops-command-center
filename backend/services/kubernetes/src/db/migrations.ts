/**
 * Postgres schema migrations for the kubernetes-service.
 *
 * Kept as a TS module (not `.sql` files on disk) so the migration
 * source ships with the compiled `dist/` output with no extra copy
 * step — see `@aicc/shared/db`'s `migrate()`.
 */
import type { Queryable, Migration } from '@aicc/shared/db';
import { decryptSecret, encryptSecret, type Keyring } from '@aicc/shared/crypto';
import type { Logger } from '@aicc/shared';

export const MIGRATIONS: Migration[] = [
  {
    name: '001_clusters',
    sql: `
      CREATE TABLE clusters (
        id uuid PRIMARY KEY,
        tenant_id uuid NOT NULL,
        name text NOT NULL,
        provider text NOT NULL,
        environment text NOT NULL DEFAULT 'dev',
        labels jsonb NOT NULL DEFAULT '{}'::jsonb,
        server text,
        token text,
        ca_bundle text,
        insecure_skip_verify boolean NOT NULL DEFAULT false,
        k8s_version text,
        region text,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX clusters_tenant_id_idx ON clusters (tenant_id);
    `,
  },
  {
    // See ADR-0016: credentials move from plain `token`/`ca_bundle`
    // columns to these `_enc` columns. The plain columns are kept
    // (and nulled out by `migrateCredentials` below) until a later
    // migration drops them once every environment has re-encrypted.
    name: '002_cluster_credential_columns',
    sql: `
      ALTER TABLE clusters ADD COLUMN token_enc text;
      ALTER TABLE clusters ADD COLUMN ca_bundle_enc text;
      ALTER TABLE clusters ADD COLUMN credential_key_id text;
    `,
  },
];

const BATCH_SIZE = 100;

interface PlaintextCredentialRow {
  id: string;
  token: string | null;
  ca_bundle: string | null;
}

/**
 * One-shot, idempotent re-encryption of any cluster rows still holding
 * plaintext `token`/`ca_bundle` values. Safe to call on every boot: once
 * a row's plaintext columns are nulled out it no longer matches the
 * `WHERE` clause, so re-running this is a no-op.
 */
export async function migrateCredentials(
  db: Queryable,
  keyring: Keyring,
  logger: Logger,
): Promise<void> {
  let migrated = 0;
  for (;;) {
    const { rows } = await db.query<PlaintextCredentialRow>(
      `SELECT id, token, ca_bundle FROM clusters
       WHERE token IS NOT NULL OR ca_bundle IS NOT NULL
       LIMIT $1`,
      [BATCH_SIZE],
    );
    if (rows.length === 0) break;
    for (const row of rows) {
      const tokenEnc = row.token != null ? encryptSecret(keyring, row.token) : null;
      const caBundleEnc = row.ca_bundle != null ? encryptSecret(keyring, row.ca_bundle) : null;
      await db.query(
        `UPDATE clusters
         SET token_enc = $2, ca_bundle_enc = $3, credential_key_id = $4, token = NULL, ca_bundle = NULL
         WHERE id = $1`,
        [row.id, tokenEnc, caBundleEnc, keyring.activeKeyId],
      );
      migrated++;
    }
    if (rows.length < BATCH_SIZE) break;
  }
  if (migrated > 0) {
    logger.info({ migrated }, 'kubernetes-service: re-encrypted cluster credentials at rest');
  }
}

interface StaleCiphertextRow {
  id: string;
  token_enc: string | null;
  ca_bundle_enc: string | null;
}

/**
 * Forces re-encryption of any row whose ciphertext was written under a
 * key other than the keyring's current active key (`credential_key_id`
 * tracks which key a row is under, so this is a cheap indexed-free scan
 * rather than decrypting every row to inspect the ciphertext). Run at
 * startup, after `migrateCredentials`, whenever a keyring is configured
 * — this is the key-rotation step: keep the old key present in the
 * keyring (so old ciphertexts still decrypt) until this pass has moved
 * every row onto the new active key, then the old key can be dropped.
 *
 * Idempotent: once a row is re-encrypted its `credential_key_id` is set
 * to the active key id, so it no longer matches the `WHERE` clause.
 */
export async function reencryptCredentials(
  db: Queryable,
  keyring: Keyring,
  logger: Logger,
): Promise<void> {
  let reencrypted = 0;
  for (;;) {
    const { rows } = await db.query<StaleCiphertextRow>(
      `SELECT id, token_enc, ca_bundle_enc FROM clusters
       WHERE (token_enc IS NOT NULL OR ca_bundle_enc IS NOT NULL)
         AND credential_key_id <> $1
       LIMIT $2`,
      [keyring.activeKeyId, BATCH_SIZE],
    );
    if (rows.length === 0) break;
    for (const row of rows) {
      const tokenEnc =
        row.token_enc != null
          ? encryptSecret(keyring, decryptSecret(keyring, row.token_enc))
          : null;
      const caBundleEnc =
        row.ca_bundle_enc != null
          ? encryptSecret(keyring, decryptSecret(keyring, row.ca_bundle_enc))
          : null;
      await db.query(
        `UPDATE clusters
         SET token_enc = $2, ca_bundle_enc = $3, credential_key_id = $4
         WHERE id = $1`,
        [row.id, tokenEnc, caBundleEnc, keyring.activeKeyId],
      );
      reencrypted++;
    }
    if (rows.length < BATCH_SIZE) break;
  }
  if (reencrypted > 0) {
    logger.info(
      { reencrypted, activeKeyId: keyring.activeKeyId },
      'kubernetes-service: re-encrypted cluster credentials under the active key',
    );
  }
}
