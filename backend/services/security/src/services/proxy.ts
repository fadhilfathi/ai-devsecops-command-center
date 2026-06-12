/**
 * Generic HTTP proxy for downstream services.
 *
 * Used by the security-service S2.5 endpoints to forward requests to
 * the Python agent fleet (sbom-pipeline-service, vuln-intel-service,
 * dependency-intel-service) and to capture the response for OpenAPI
 * documentation.
 *
 * Behaviour:
 *   - JSON request body, JSON response body (caller-supplied Zod schema)
 *   - 30s default timeout, AbortController-based cancellation
 *   - 502 UPSTREAM_FAILURE if the downstream is unreachable or returns
 *     a non-2xx; the body is preserved when the JSON is parseable
 *   - Adds an `X-Request-Id` (forwarded from `X-Request-Id` header if
 *     present, otherwise generated) for distributed tracing
 *   - Adds a `User-Agent: aicc-security-service/<version>` header
 */
import { randomUUID } from 'node:crypto';
import { AppError, type Logger } from '@aicc/shared';

export interface ProxyOptions {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  logger?: Logger;
  timeoutMs?: number;
  requestId?: string;
  serviceVersion?: string;
}

export interface ProxyResult<T> {
  status: number;
  body: T;
  requestId: string;
  upstreamUrl: string;
  durationMs: number;
}

export async function proxyRequest<T = unknown>(opts: ProxyOptions): Promise<ProxyResult<T>> {
  const method = opts.method ?? 'POST';
  const requestId = opts.requestId ?? (randomUUID() as string);
  const timeoutMs = opts.timeoutMs ?? 30_000;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Request-Id': requestId,
      'User-Agent': `aicc-security-service/${opts.serviceVersion ?? '0.2.0'}`,
      ...(opts.headers ?? {}),
    };

    const res = await fetch(opts.url, {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed: T;
    try {
      parsed = (text ? JSON.parse(text) : ({} as T)) as T;
    } catch {
      // Upstream returned non-JSON; preserve as a string cast.
      parsed = text as unknown as T;
    }

    if (!res.ok) {
      opts.logger?.warn(
        { url: opts.url, method, status: res.status, requestId, durationMs: Date.now() - start },
        'upstream returned non-2xx',
      );
      throw new AppError(
        'UPSTREAM_FAILURE',
        `Upstream ${opts.url} returned ${res.status}`,
        { statusCode: 502, details: { upstreamStatus: res.status, upstreamBody: parsed, requestId } },
      );
    }

    return {
      status: res.status,
      body: parsed,
      requestId,
      upstreamUrl: opts.url,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    if ((err as { name?: string }).name === 'AbortError') {
      throw new AppError('UPSTREAM_FAILURE', `Upstream ${opts.url} timed out after ${timeoutMs}ms`, {
        statusCode: 504,
        details: { requestId, timeoutMs },
      });
    }
    if (err instanceof AppError) throw err;
    throw new AppError('UPSTREAM_FAILURE', `Upstream ${opts.url} unreachable: ${(err as Error).message}`, {
      statusCode: 502,
      details: { requestId, cause: (err as Error).message },
    });
  } finally {
    clearTimeout(timer);
  }
}
