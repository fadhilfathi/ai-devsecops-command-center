/**
 * Minimal GitHub REST client for remediation follow-ups: opening an
 * issue or pull request carrying a RemediationAgent proposal's
 * manifest hint. Node's native `fetch` is the only HTTP dependency;
 * `fetchImpl` is injectable for tests.
 *
 * Errors carry the response status ONLY — GitHub's response body is
 * never propagated to callers (see the remediation route, which maps
 * failures to a generic 502).
 */
export class GithubApiError extends Error {
  readonly status: number;
  constructor(status: number) {
    super(`GitHub API request failed with status ${status}`);
    this.name = 'GithubApiError';
    this.status = status;
  }
}

export interface GithubClientOptions {
  token: string;
  owner: string;
  repo: string;
  /** Override for GHES; defaults to `GITHUB_API_URL`'s documented value. */
  baseUrl?: string;
  fetchImpl?: typeof globalThis.fetch;
}

export interface GithubIssueInput {
  title: string;
  body: string;
}

export interface GithubPullRequestInput {
  title: string;
  body: string;
  head: string;
  base?: string;
}

export interface GithubRef {
  url: string;
  number: number;
}

const REQUEST_TIMEOUT_MS = 10_000;

function parseRef(json: unknown): GithubRef {
  if (typeof json === 'object' && json !== null) {
    const { html_url: url, number } = json as { html_url?: unknown; number?: unknown };
    if (typeof url === 'string' && typeof number === 'number') return { url, number };
  }
  throw new Error('unexpected GitHub response shape');
}

export class GithubClient {
  private readonly token: string;
  private readonly repoPath: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(opts: GithubClientOptions) {
    this.token = opts.token;
    this.repoPath = `/repos/${encodeURIComponent(opts.owner)}/${encodeURIComponent(opts.repo)}`;
    this.baseUrl = (opts.baseUrl ?? 'https://api.github.com').replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  }

  createIssue(input: GithubIssueInput): Promise<GithubRef> {
    return this.post(`${this.repoPath}/issues`, { title: input.title, body: input.body });
  }

  createPullRequest(input: GithubPullRequestInput): Promise<GithubRef> {
    return this.post(`${this.repoPath}/pulls`, {
      title: input.title,
      body: input.body,
      head: input.head,
      ...(input.base ? { base: input.base } : {}),
    });
  }

  private async post(path: string, payload: Record<string, unknown>): Promise<GithubRef> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${this.token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'AICC-Integration-Service',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) throw new GithubApiError(res.status);
    return parseRef(await res.json());
  }
}
