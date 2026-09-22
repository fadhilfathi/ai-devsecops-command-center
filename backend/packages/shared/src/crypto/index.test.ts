import { describe, expect, it } from 'vitest';
import {
  createCipherKeyring,
  decryptSecret,
  encryptSecret,
  generateKey,
  parseKeyring,
  CryptoConfigError,
  DecryptError,
} from './index.js';

const KEY_A = generateKey();
const KEY_B = generateKey();

describe('parseKeyring', () => {
  it('parses a single key entry, first entry active', () => {
    const kr = parseKeyring(`v1:${KEY_A}`);
    expect(kr.activeKeyId).toBe('v1');
    expect(kr.keys.size).toBe(1);
  });

  it('parses multiple entries and keeps the first as active', () => {
    const kr = parseKeyring(`v2:${KEY_B},v1:${KEY_A}`);
    expect(kr.activeKeyId).toBe('v2');
    expect(kr.keys.size).toBe(2);
  });

  it('rejects a key of the wrong length', () => {
    expect(() => parseKeyring('v1:dG9vc2hvcnQ=')).toThrow(CryptoConfigError);
  });

  it('rejects malformed entries', () => {
    expect(() => parseKeyring('not-a-valid-entry')).toThrow(CryptoConfigError);
  });

  it('rejects an empty value', () => {
    expect(() => parseKeyring('')).toThrow(CryptoConfigError);
  });
});

describe('createCipherKeyring', () => {
  it('rejects when activeKeyId is not in keys', () => {
    expect(() =>
      createCipherKeyring({ keys: { v1: Buffer.from(KEY_A, 'base64') }, activeKeyId: 'v2' }),
    ).toThrow(CryptoConfigError);
  });
});

describe('encryptSecret / decryptSecret', () => {
  it('round-trips a value', () => {
    const kr = parseKeyring(`v1:${KEY_A}`);
    const ct = encryptSecret(kr, 'super-secret-token');
    expect(ct).not.toContain('super-secret-token');
    expect(decryptSecret(kr, ct)).toBe('super-secret-token');
  });

  it('detects tampering', () => {
    const kr = parseKeyring(`v1:${KEY_A}`);
    const ct = encryptSecret(kr, 'super-secret-token');
    const parts = ct.split('.');
    // flip a byte in the ciphertext segment
    const ctBuf = Buffer.from(parts[4]!, 'base64');
    ctBuf[0] = ctBuf[0]! ^ 0xff;
    parts[4] = ctBuf.toString('base64');
    expect(() => decryptSecret(kr, parts.join('.'))).toThrow(DecryptError);
  });

  it('throws on unknown key id', () => {
    const kr1 = parseKeyring(`v1:${KEY_A}`);
    const kr2 = parseKeyring(`v2:${KEY_B}`);
    const ct = encryptSecret(kr1, 'value');
    expect(() => decryptSecret(kr2, ct)).toThrow(DecryptError);
  });

  it('supports rotation: decrypts old ciphertexts after the active key changes', () => {
    const krOld = parseKeyring(`v1:${KEY_A}`);
    const ct = encryptSecret(krOld, 'value');
    const krNew = parseKeyring(`v2:${KEY_B},v1:${KEY_A}`);
    expect(krNew.activeKeyId).toBe('v2');
    expect(decryptSecret(krNew, ct)).toBe('value');
    const ctNew = encryptSecret(krNew, 'value2');
    expect(ctNew.split('.')[1]).toBe('v2');
  });

  it('rejects malformed input', () => {
    const kr = parseKeyring(`v1:${KEY_A}`);
    expect(() => decryptSecret(kr, 'not-a-ciphertext')).toThrow(DecryptError);
  });

  it('rejects plaintext unless explicitly allowed', () => {
    const kr = parseKeyring(`v1:${KEY_A}`);
    expect(() => decryptSecret(kr, 'plain-old-token')).toThrow(DecryptError);
    expect(decryptSecret(kr, 'plain-old-token', { allowPlaintext: true })).toBe('plain-old-token');
  });
});
