/**
 * AES-256-GCM envelope encryption for secrets stored at rest (see
 * ADR-0016). No third-party crypto deps — `node:crypto` covers it.
 *
 * Ciphertext format: `v1.<keyId>.<iv-b64>.<tag-b64>.<ct-b64>`. The key
 * id is also passed as AAD so a ciphertext produced under one key id
 * cannot be replayed as if it belonged to another.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;
const FORMAT_VERSION = 'v1';

export class CryptoConfigError extends Error {}
export class DecryptError extends Error {}

export interface Keyring {
  activeKeyId: string;
  keys: Map<string, Buffer>;
}

/**
 * Parses `keyId:base64key[,keyId:base64key...]` (the `AICC_CREDENTIAL_KEYS`
 * env var format). The first entry is the active key; the rest are kept
 * around so old ciphertexts remain decryptable during rotation.
 */
export function parseKeyring(value: string): Keyring {
  const entries = value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (entries.length === 0) {
    throw new CryptoConfigError('keyring value has no entries');
  }
  const keys = new Map<string, Buffer>();
  let activeKeyId: string | undefined;
  for (const entry of entries) {
    const idx = entry.indexOf(':');
    if (idx < 0) {
      throw new CryptoConfigError(`malformed keyring entry: ${entry}`);
    }
    const keyId = entry.slice(0, idx);
    const key = Buffer.from(entry.slice(idx + 1), 'base64');
    if (key.length !== KEY_BYTES) {
      throw new CryptoConfigError(`key "${keyId}" must decode to ${KEY_BYTES} bytes`);
    }
    keys.set(keyId, key);
    if (activeKeyId === undefined) activeKeyId = keyId;
  }
  return { activeKeyId: activeKeyId!, keys };
}

export function createCipherKeyring(opts: {
  keys: Record<string, Buffer>;
  activeKeyId: string;
}): Keyring {
  const keys = new Map(Object.entries(opts.keys));
  for (const [keyId, key] of keys) {
    if (key.length !== KEY_BYTES) {
      throw new CryptoConfigError(`key "${keyId}" must be ${KEY_BYTES} bytes`);
    }
  }
  if (!keys.has(opts.activeKeyId)) {
    throw new CryptoConfigError(`activeKeyId "${opts.activeKeyId}" not present in keys`);
  }
  return { activeKeyId: opts.activeKeyId, keys };
}

export function encryptSecret(keyring: Keyring, plaintext: string): string {
  const keyId = keyring.activeKeyId;
  const key = keyring.keys.get(keyId);
  if (!key) throw new CryptoConfigError(`active key "${keyId}" not found in keyring`);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  cipher.setAAD(Buffer.from(keyId, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    FORMAT_VERSION,
    keyId,
    iv.toString('base64'),
    tag.toString('base64'),
    ct.toString('base64'),
  ].join('.');
}

export function decryptSecret(
  keyring: Keyring,
  value: string,
  opts?: { allowPlaintext?: boolean },
): string {
  const parts = value.split('.');
  if (parts.length !== 5 || parts[0] !== FORMAT_VERSION) {
    if (opts?.allowPlaintext) return value;
    throw new DecryptError('malformed ciphertext value');
  }
  const [, keyId, ivB64, tagB64, ctB64] = parts;
  const key = keyring.keys.get(keyId!);
  if (!key) throw new DecryptError(`unknown key id "${keyId}"`);
  let iv: Buffer, tag: Buffer, ct: Buffer;
  try {
    iv = Buffer.from(ivB64!, 'base64');
    tag = Buffer.from(tagB64!, 'base64');
    ct = Buffer.from(ctB64!, 'base64');
  } catch {
    throw new DecryptError('malformed ciphertext value');
  }
  if (iv.length !== IV_BYTES) throw new DecryptError('malformed ciphertext value');
  try {
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAAD(Buffer.from(keyId!, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    throw new DecryptError('ciphertext authentication failed');
  }
}

/** Generates a base64-encoded 32-byte key, for docs/ops key generation. */
export function generateKey(): string {
  return randomBytes(KEY_BYTES).toString('base64');
}
