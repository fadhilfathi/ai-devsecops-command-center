import { test, expect } from 'vitest';
import { checkServerUrl, checkServerUrlDns, type HostnameResolver } from './ssrf-guard.js';

test('SSRF guard policy table', () => {
  const cases: [string, boolean, boolean][] = [
    // [url, allowPrivateApi, expectedOk]
    ['https://169.254.169.254', false, false],
    ['https://169.254.169.254', true, false], // metadata never allowed
    ['http://api.example.com', false, false], // non-https
    ['https://127.0.0.1', false, false],
    ['https://127.0.0.1', true, true], // AICC_K8S_ALLOW_PRIVATE_API
    ['https://10.0.0.5', false, true], // RFC1918 allowed by default
    ['https://[fd00:ec2::254]', false, false],
    ['https://[fd00:ec2::254]', true, false], // metadata never allowed
    ['https://[::1]', false, false],
    ['https://api.prod.example.com', false, true], // DNS hostname, not classified
  ];

  for (const [url, allowPrivateApi, expectedOk] of cases) {
    const res = checkServerUrl(url, { allowPrivateApi });
    expect(res.ok).toBe(expectedOk);
  }
});

function resolverFor(addresses: string[]): HostnameResolver {
  return async () => addresses.map((address) => ({ address }));
}

test('checkServerUrlDns rejects a hostname resolving to a metadata address', async () => {
  const res = await checkServerUrlDns('https://metadata.attacker.example', {
    allowPrivateApi: false,
    resolveHostname: resolverFor(['169.254.169.254']),
  });
  expect(res.ok).toBe(false);
});

test('checkServerUrlDns accepts a hostname resolving to an RFC1918 address', async () => {
  const res = await checkServerUrlDns('https://api.internal.example', {
    allowPrivateApi: false,
    resolveHostname: resolverFor(['10.0.0.5']),
  });
  expect(res.ok).toBe(true);
});

test('checkServerUrlDns rejects if any resolved address is forbidden', async () => {
  const res = await checkServerUrlDns('https://multi.example.com', {
    allowPrivateApi: false,
    resolveHostname: resolverFor(['203.0.113.10', '127.0.0.1']),
  });
  expect(res.ok).toBe(false);
});

test('checkServerUrlDns fails closed when resolution throws', async () => {
  const res = await checkServerUrlDns('https://broken.example.com', {
    allowPrivateApi: false,
    resolveHostname: async () => {
      throw new Error('ENOTFOUND');
    },
  });
  expect(res.ok).toBe(false);
});

test('checkServerUrlDns skips DNS resolution for IP literals', async () => {
  const resolve = resolverFor(['169.254.169.254']);
  const res = await checkServerUrlDns('https://10.0.0.5', {
    allowPrivateApi: false,
    resolveHostname: resolve,
  });
  expect(res.ok).toBe(true);
});

test.each([
  ['::ffff:169.254.169.254'],
  ['::ffff:a9fe:a9fe'],
  ['64:ff9b::169.254.169.254'],
  ['::169.254.169.254'],
  ['0.0.0.0'],
  ['::'],
  ['::ffff:127.0.0.1'],
  ['100.100.100.200'],
])('resolved address %s is rejected', async (address) => {
  const result = await checkServerUrlDns('https://cluster.example.test', {
    allowPrivateApi: false,
    resolveHostname: resolverFor([address]),
  });
  expect(result.ok).toBe(false);
});

test.each([['https://[::ffff:169.254.169.254]'], ['https://0.0.0.0'], ['https://[::]']])(
  'literal %s is rejected',
  (url) => {
    expect(checkServerUrl(url, { allowPrivateApi: false }).ok).toBe(false);
  },
);
