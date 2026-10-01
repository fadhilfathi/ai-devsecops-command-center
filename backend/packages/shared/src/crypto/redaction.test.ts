import { describe, expect, it } from 'vitest';
import {
  CryptoConfigError,
  DecryptError,
  decryptSecret,
  encryptSecret,
  generateKey,
  parseKeyring,
} from './index.js';

// A key pasted without its `keyId:` prefix (or with the separator mangled)
// must be identified by position in errors, never by value: these messages
// can surface in HTTP responses.
describe('crypto error messages never echo key material', () => {
  it('parseKeyring: a separator-less entry is identified by position, not value', () => {
    const pastedKey = generateKey();
    let message = '';
    try {
      parseKeyring(`k-good:${generateKey()},${pastedKey}`);
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoConfigError);
      message = (err as Error).message;
    }
    expect(message).not.toBe('');
    expect(message).not.toContain(pastedKey);
  });

  it('parseKeyring: a reversed entry (key before the colon) never echoes the key', () => {
    const pastedKey = generateKey();
    let message = '';
    try {
      parseKeyring(`${pastedKey}:not-a-key-id`);
    } catch (err) {
      expect(err).toBeInstanceOf(CryptoConfigError);
      message = (err as Error).message;
    }
    expect(message).not.toBe('');
    expect(message).not.toContain(pastedKey);
  });

  it('decryptSecret: an unknown key id never echoes value-derived bytes', () => {
    const ct = encryptSecret(parseKeyring(`v1:${generateKey()}`), 'super-secret-token');
    const foreign = ct.split('.');
    foreign[1] = generateKey();
    let message = '';
    try {
      decryptSecret(parseKeyring(`v2:${generateKey()}`), foreign.join('.'));
    } catch (err) {
      expect(err).toBeInstanceOf(DecryptError);
      message = (err as Error).message;
    }
    expect(message).not.toBe('');
    expect(message).not.toContain(foreign[1]!);
    expect(message).not.toContain('super-secret-token');
  });
});
