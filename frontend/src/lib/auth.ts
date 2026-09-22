/**
 * Dev-login auth client (S6-2).
 *
 * `login(email)` hits auth-service's `POST /v1/auth/dev-login` (the only
 * entry point — auth-service's user repository is seed-only with no
 * password hashes, so there's no real credential login yet) and keeps
 * the access token in memory + `sessionStorage` (survives a reload,
 * cleared when the tab closes). `api.ts` sends it as `Authorization: Bearer`.
 */
import { useSyncExternalStore } from 'react';

const STORAGE_KEY = 'aicc_access_token';

function readStoredToken(): string | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

let token: string | null = readStoredToken();
// Set when a request 401s after we had a token (or tried the legacy
// header fallback) — tells api.ts to stop retrying the stale
// `x-tenant-id` fallback and tells the app shell to show the login gate.
let authRequired = false;
const listeners = new Set<() => void>();

function setToken(next: string | null): void {
  token = next;
  try {
    if (typeof sessionStorage !== 'undefined') {
      if (next) sessionStorage.setItem(STORAGE_KEY, next);
      else sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // sessionStorage unavailable (e.g. private mode) — memory-only fallback.
  }
  for (const listener of listeners) listener();
}

/** Current access token, or null if logged out. */
export function getToken(): string | null {
  return token;
}

/** Log in via auth-service's dev-login endpoint. Throws on failure. */
export async function login(email: string): Promise<void> {
  const res = await fetch('/api/auth/dev-login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    throw new Error(`login failed: HTTP ${res.status}`);
  }
  const body = (await res.json()) as { accessToken: string };
  authRequired = false;
  setToken(body.accessToken);
}

/** Clear the token — called explicitly (user-initiated logout). */
export function logout(): void {
  authRequired = false;
  setToken(null);
}

/**
 * Called by `api.ts` when a request 401s. Clears the token and sets
 * `authRequired` so the app shell shows the login gate and `api.ts` stops
 * sending the stale `x-tenant-id` fallback on subsequent calls.
 */
export function sessionExpired(): void {
  authRequired = true;
  setToken(null);
}

/** Whether a request has 401'd since the last successful login. */
export function isAuthRequired(): boolean {
  return authRequired;
}

/** React hook for auth state — used to gate the app and drive the logout button. */
export function useAuth(): {
  token: string | null;
  isAuthenticated: boolean;
  authRequired: boolean;
} {
  const current = useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, getToken);
  return { token: current, isAuthenticated: current !== null, authRequired };
}
