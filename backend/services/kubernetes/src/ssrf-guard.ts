/**
 * SSRF guard for cluster `server` URLs.
 *
 * The `server` field points *this service* at an arbitrary host, so a
 * malicious or careless value can be used to make kubernetes-service
 * issue requests to internal infrastructure (cloud metadata endpoints,
 * loopback, etc). Policy:
 *
 *   - https only (plaintext http is never accepted for a real cluster).
 *   - link-local / cloud-metadata addresses (169.254.0.0/16, the AWS
 *     EKS Fargate IPv6 metadata address fd00:ec2::254) are always
 *     rejected — there is no legitimate reason for a cluster API server
 *     to live there.
 *   - RFC1918 private ranges (10/8, 172.16/12, 192.168/16) and IPv6
 *     unique-local addresses are allowed by default: on-prem/private
 *     cluster API servers are the common case.
 *   - loopback is rejected by default (a real cluster is never on
 *     localhost) unless `AICC_K8S_ALLOW_PRIVATE_API=true`, which also
 *     covers local dev against a port-forwarded/kind API server.
 *
 * `checkServerUrl` only classifies IP literals — a DNS hostname is
 * passed through unclassified. `checkServerUrlDns` (below) resolves
 * hostnames and applies the same policy to every returned address.
 */
import { isIP } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';

export type ServerUrlCheckResult = { ok: true } | { ok: false; reason: string };

function ipv4Octets(host: string): number[] | undefined {
  const octets = host.split('.').map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return undefined;
  }
  return octets;
}

type Ipv4Class = 'loopback' | 'link-local' | 'metadata' | 'private' | 'public';

function classifyIpv4(host: string): Ipv4Class {
  const octets = ipv4Octets(host);
  if (!octets) return 'public';
  const [a, b] = octets as [number, number, number, number];
  // 0.0.0.0/8 is "this host": connecting to it reaches localhost.
  if (a === 0) return 'loopback';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link-local';
  // Alibaba Cloud metadata endpoint sits inside the CGNAT range.
  if (host === '100.100.100.200') return 'metadata';
  if (a === 100 && b >= 64 && b <= 127) return 'private';
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  return 'public';
}

type Ipv6Class = 'loopback' | 'link-local' | 'metadata' | 'private' | 'public';

/** AWS EKS Fargate / IMDSv6 metadata address. Always blocked. */
const IPV6_METADATA = 'fd00:ec2::254';

function normalizeIpv6(host: string): string {
  return host.replace(/^\[|\]$/g, '').toLowerCase();
}

/**
 * IPv6 forms that carry an IPv4 address and are routed to it:
 * IPv4-mapped (::ffff:a.b.c.d / ::ffff:hhhh:hhhh), IPv4-compatible
 * (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d / 64:ff9b::hhhh:hhhh).
 */
function embeddedIpv4(h: string): string | undefined {
  const m =
    /^(?:::ffff:|::|64:ff9b::)(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(h);
  if (!m) return undefined;
  if (m[1]) return m[1];
  const hi = parseInt(m[2]!, 16);
  const lo = parseInt(m[3]!, 16);
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

function classifyIpv6(host: string): Ipv6Class | Ipv4Class {
  const h = normalizeIpv6(host);
  const v4 = embeddedIpv4(h);
  if (v4) return classifyIpv4(v4);
  if (h === '::1' || h === '::') return 'loopback';
  if (h === IPV6_METADATA) return 'metadata';
  // fe80::/10 link-local
  if (/^fe[89ab][0-9a-f]:/.test(h)) return 'link-local';
  // fc00::/7 unique-local (private)
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return 'private';
  return 'public';
}

/** Classifies an IP literal (v4 or v6); returns undefined if it's not an IP. */
function classifyAddress(address: string): Ipv4Class | Ipv6Class | undefined {
  const version = isIP(address);
  if (version === 4) return classifyIpv4(address);
  if (version === 6) return classifyIpv6(address);
  return undefined;
}

/** Shared policy decision for a classified address kind. undefined = allowed. */
function policyReasonFor(
  kind: Ipv4Class | Ipv6Class,
  opts: ServerUrlCheckOptions,
): string | undefined {
  if (kind === 'link-local' || kind === 'metadata') {
    return 'link-local/metadata addresses are not allowed';
  }
  if (kind === 'loopback' && !opts.allowPrivateApi) {
    return 'loopback addresses are not allowed unless AICC_K8S_ALLOW_PRIVATE_API=true';
  }
  return undefined;
}

/** Injectable hostname resolver so callers/tests don't have to hit real DNS. */
export type HostnameResolver = (hostname: string) => Promise<{ address: string }[]>;

async function defaultResolver(hostname: string): Promise<{ address: string }[]> {
  return dnsLookup(hostname, { all: true });
}

export interface ServerUrlCheckOptions {
  /** AICC_K8S_ALLOW_PRIVATE_API — allow loopback addresses. Never widens link-local/metadata. */
  allowPrivateApi: boolean;
  /** Defaults to `node:dns/promises` `lookup`. Override in tests to avoid real DNS. */
  resolveHostname?: HostnameResolver;
}

/** Validates a cluster `server` URL against the SSRF policy above (IP literals only). */
export function checkServerUrl(rawUrl: string, opts: ServerUrlCheckOptions): ServerUrlCheckResult {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'invalid server URL' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, reason: 'server URL must use https' };
  }

  // WHATWG URL keeps the brackets on an IPv6 hostname (`[::1]`); `net.isIP`
  // requires the bare address.
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const kind = classifyAddress(host);
  if (kind) {
    const reason = policyReasonFor(kind, opts);
    if (reason) return { ok: false, reason };
  }
  return { ok: true };
}

/**
 * DNS-resolving SSRF check.
 *
 * `checkServerUrl` lets a DNS hostname through unclassified, and even a
 * hostname that resolves to a safe address at validation time can be
 * repointed at 169.254.169.254 / loopback afterwards (DNS rebinding).
 * This resolves the hostname and applies the same policy to *every*
 * returned address, rejecting if any one of them is forbidden. Meant to
 * be run both at create/test-connection time and again at connect time
 * (`LiveProvider`) so a post-creation rebind is still caught. Resolution
 * failure fails closed (rejected).
 *
 * ponytail: `@kubernetes/client-node` re-resolves the hostname itself on
 * every HTTP request it makes, so the DNS answer can still change
 * between this check and the moment the client actually dials out
 * (TOCTOU) — a very fast rebind timed against a connect-time check would
 * still slip through. Closing that fully needs IP pinning (resolve once,
 * connect to the resolved IP, set Host/SNI from the hostname) in the
 * client-node HTTP agent; not worth building until this is observed
 * exploited in practice.
 */
export async function checkServerUrlDns(
  rawUrl: string,
  opts: ServerUrlCheckOptions,
): Promise<ServerUrlCheckResult> {
  const literal = checkServerUrl(rawUrl, opts);
  if (!literal.ok) return literal;

  const host = new URL(rawUrl).hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) return { ok: true }; // already classified by checkServerUrl above

  const resolve = opts.resolveHostname ?? defaultResolver;
  let addresses: { address: string }[];
  try {
    addresses = await resolve(host);
  } catch {
    return { ok: false, reason: 'failed to resolve server hostname' };
  }
  if (addresses.length === 0) {
    return { ok: false, reason: 'server hostname did not resolve to any address' };
  }
  for (const { address } of addresses) {
    const kind = classifyAddress(address);
    if (!kind) continue;
    const reason = policyReasonFor(kind, opts);
    if (reason) return { ok: false, reason };
  }
  return { ok: true };
}
