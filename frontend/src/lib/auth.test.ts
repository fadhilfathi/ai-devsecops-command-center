import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { login, logout, getToken } from './auth';

beforeEach(() => {
  logout();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('auth', () => {
  it('stores the token from a successful dev-login and sends it back', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ accessToken: 'token-123' }),
    });
    vi.stubGlobal('fetch', fetchSpy);

    await login('admin@aicc.local');

    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/auth/dev-login',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(getToken()).toBe('token-123');
  });

  it('throws on a failed login and leaves the token unset', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 404 });
    vi.stubGlobal('fetch', fetchSpy);

    await expect(login('nobody@aicc.local')).rejects.toThrow();
    expect(getToken()).toBeNull();
  });

  it('logout clears the token', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ accessToken: 'token-456' }),
    });
    vi.stubGlobal('fetch', fetchSpy);

    await login('admin@aicc.local');
    expect(getToken()).toBe('token-456');

    logout();
    expect(getToken()).toBeNull();
  });
});
