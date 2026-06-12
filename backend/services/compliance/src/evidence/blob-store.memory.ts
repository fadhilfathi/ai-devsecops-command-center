// In-memory blob store
//
// Local store for Sprint 2 dev and tests. Sprint 3 swaps this for the
// cloud-provider adapter (S3 / GCS / Azure Blob) without changing any
// call sites.

import { createHash } from 'node:crypto';
import type { BlobStore } from './evidence-attacher.js';

export class InMemoryBlobStore implements BlobStore {
  private readonly objects = new Map<string, { body: Buffer; contentType: string; size: number; hash: string }>();

  async put(key: string, body: Buffer | Uint8Array | string, contentType: string) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : Buffer.from(body));
    const hash = createHash('sha256').update(buf).digest('hex');
    this.objects.set(key, { body: buf, contentType, size: buf.length, hash: `sha256:${hash}` });
    return { key, hash: `sha256:${hash}`, size: buf.length };
  }

  async get(key: string): Promise<Buffer | null> {
    return this.objects.get(key)?.body ?? null;
  }
}
