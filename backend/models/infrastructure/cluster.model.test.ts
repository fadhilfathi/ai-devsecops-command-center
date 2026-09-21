import { test, expect } from 'vitest';
import { ClusterSchema } from './cluster.model.js';

function validCluster() {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    tenantId: '22222222-2222-4222-8222-222222222222',
    name: 'prod-cluster',
    provider: 'eks',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-02T00:00:00Z',
  };
}

test('parses a valid cluster with defaults applied', () => {
  const parsed = ClusterSchema.parse(validCluster());
  expect(parsed.name).toBe('prod-cluster');
  expect(parsed.phase).toBe('active');
  expect(parsed.environment).toBe('dev');
  expect(parsed.nodes).toEqual([]);
});

test('rejects a cluster with an invalid id', () => {
  const invalid = { ...validCluster(), id: 'not-a-uuid' };
  expect(() => ClusterSchema.parse(invalid)).toThrow();
});
