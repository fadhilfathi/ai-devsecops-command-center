/**
 * Cluster credential encryption keyring — see ADR-0016. Mirrors the
 * production/dev split `loadServiceConfig`'s `loadAuthConfig` uses for
 * `AUTH_JWT_SECRET`: production refuses to boot without a valid
 * keyring, dev falls back to plaintext storage with a one-time warning.
 */
import type { Logger } from '@aicc/shared';
import { parseKeyring, type Keyring } from '@aicc/shared/crypto';

let warned = false;

export function loadCredentialKeyring(environment: string, logger: Logger): Keyring | undefined {
  const raw = process.env.AICC_CREDENTIAL_KEYS;
  if (!raw) {
    if (environment === 'production') {
      throw new Error(
        'AICC_CREDENTIAL_KEYS must be set in production (refusing to boot and store cluster credentials in plaintext)',
      );
    }
    if (!warned) {
      logger.warn(
        'AICC_CREDENTIAL_KEYS not set — cluster credentials will be stored in plaintext (dev only, see ADR-0016)',
      );
      warned = true;
    }
    return undefined;
  }

  try {
    return parseKeyring(raw);
  } catch (err) {
    if (environment === 'production') {
      throw new Error(`AICC_CREDENTIAL_KEYS is invalid: ${(err as Error).message}`, { cause: err });
    }
    if (!warned) {
      logger.warn(
        { err },
        'AICC_CREDENTIAL_KEYS is invalid — falling back to plaintext credential storage (dev only, see ADR-0016)',
      );
      warned = true;
    }
    return undefined;
  }
}
