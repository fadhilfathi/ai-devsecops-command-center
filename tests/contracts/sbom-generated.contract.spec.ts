/**
 * Contract test for `security.sbom.generated.v1`.
 *
 * Locked: 2026-06-12 (O-3.6 sbom_fingerprint + O-3.7 algorithm + format fields).
 *
 * Spec: security/wire-format/sbom-generated.schema.json
 * Operator mirror: security/README.md § "security.sbom.generated.v1 event payload (LOCKED)"
 */
import { describe, it, expect, beforeAll } from 'vitest';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// ---------- fixtures ----------

type Example = {
  description: string;
  expected: 'valid' | 'invalid';
  record: Record<string, unknown>;
};

const examplesPath = resolve(__dirname, 'fixtures/sbom-generated.examples.json');
const examples: Example[] = JSON.parse(readFileSync(examplesPath, 'utf8'));

// ---------- schema ----------

const schemaPath = resolve(
  __dirname,
  '../../security/wire-format/sbom-generated.schema.json',
);
const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));

let validate: ValidateFunction;

beforeAll(() => {
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  validate = ajv.compile(schema);
});

// ---------- schema validation ----------

describe('sbom-generated.v1 — schema validation', () => {
  for (const ex of examples) {
    it(`${ex.expected === 'valid' ? '✅ accepts' : '❌ rejects'}: ${ex.description}`, () => {
      const ok = validate(ex.record);
      if (ex.expected === 'valid') {
        if (!ok) {
          throw new Error(
            `expected record to validate, but it failed:\n` +
              JSON.stringify(validate.errors, null, 2),
          );
        }
        expect(ok).toBe(true);
      } else {
        expect(ok).toBe(false);
        expect(validate.errors?.length ?? 0).toBeGreaterThan(0);
      }
    });
  }
});

// ---------- fingerprint envelope (O-3.7) ----------

describe('sbom_fingerprint envelope', () => {
  it('the prefix in sbom_fingerprint MUST match sbom_fingerprint_algorithm', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    // O-3.7 invariant: the algorithm prefix encodes the hash, and the
    // explicit sbom_fingerprint_algorithm field carries the same value.
    // If they ever drift, downstream verifiers will silently mis-hash.
    const prefix = String(valid.sbom_fingerprint).split(':')[0];
    expect(valid.sbom_fingerprint_algorithm).toBe(prefix);
  });

  it('sbom_fingerprint_format defaults to cyclonedx-json+canonicalized-jcs', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    expect(valid.sbom_fingerprint_format).toBe('cyclonedx-json+canonicalized-jcs');
  });

  it('sbom_fingerprint_algorithm enum: sha256, sha512, blake3', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    for (const alg of ['sha256', 'sha512', 'blake3']) {
      expect(validate({ ...valid, sbom_fingerprint_algorithm: alg })).toBe(true);
    }
    for (const alg of ['md5', 'sha1', 'crc32']) {
      expect(validate({ ...valid, sbom_fingerprint_algorithm: alg })).toBe(false);
    }
  });

  it('sbom_fingerprint_format enum: the 4 versioned values', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    for (const fmt of [
      'cyclonedx-json+canonicalized-jcs',
      'cyclonedx-json+raw',
      'spdx-json+canonicalized-jcs',
      'spdx-json+raw',
    ]) {
      expect(validate({ ...valid, sbom_fingerprint_format: fmt })).toBe(true);
    }
    expect(validate({ ...valid, sbom_fingerprint_format: 'spdx-tagvalue' })).toBe(false);
  });

  it('sbom_fingerprint regex matches sha256 | sha512 | blake3 with hex', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    // Good fingerprints
    expect(
      validate({ ...valid, sbom_fingerprint: 'sha256:' + 'a'.repeat(64) }),
    ).toBe(true);
    expect(
      validate({ ...valid, sbom_fingerprint: 'sha512:' + 'a'.repeat(128) }),
    ).toBe(true);
    expect(
      validate({ ...valid, sbom_fingerprint: 'blake3:' + 'a'.repeat(64) }),
    ).toBe(true);
    // Bad fingerprints
    expect(validate({ ...valid, sbom_fingerprint: 'md5:abcdef' })).toBe(false);
    expect(validate({ ...valid, sbom_fingerprint: 'sha256:not-hex' })).toBe(false);
    expect(validate({ ...valid, sbom_fingerprint: 'sha256:' + 'a'.repeat(63) })).toBe(false); // too short
  });
});

// ---------- sbom_id schema ----------

describe('sbom_id schema', () => {
  it('MUST match the locked regex sbom-YYYY-MM-DD-<git-sha>-<scope>', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    // Good ids
    for (const scope of ['monorepo', 'service', 'package', 'container', 'fs', 'git-tree']) {
      expect(
        validate({ ...valid, sbom_id: `sbom-2026-06-12-a1b2c3d-${scope}` }),
      ).toBe(true);
    }
    // Bad ids
    expect(validate({ ...valid, sbom_id: '2026-06-12-a1b2c3d-monorepo' })).toBe(false); // missing sbom- prefix
    expect(validate({ ...valid, sbom_id: 'sbom-2026/06/12-a1b2c3d-monorepo' })).toBe(false); // slashes
    expect(validate({ ...valid, sbom_id: 'sbom-2026-06-12-a1b2c3d-other' })).toBe(false); // bad scope
  });
});

// ---------- required-field count parity with the JSON Schema ----------

describe('required-field count parity with the JSON Schema', () => {
  it('the JSON Schema has 13 required fields (O-3.7)', () => {
    expect(Array.isArray(schema.required)).toBe(true);
    expect(schema.required.length).toBe(13);
  });
  it('all required fields are present on the positive example', () => {
    const valid = examples.find((e) => e.expected === 'valid')!.record;
    for (const f of schema.required) {
      expect(valid, `positive example missing required field ${f}`).toHaveProperty(f);
    }
  });
});
