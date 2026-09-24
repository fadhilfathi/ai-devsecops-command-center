# Quick start

A from-scratch path to a running AI-DevSecOps Command Center — either just
the UI with sample data, or the full docker-compose stack.

> Every command below was verified against the code that runs it as of this
> writing. If something doesn't match, the code changed — please open an
> issue.

## Prerequisites

- **Node.js `>= 22.12.0`** (pinned in [`.nvmrc`](../.nvmrc) and
  `package.json#engines`). `nvm use` after cloning.
- **pnpm `>= 9`**: `corepack enable` or `npm i -g pnpm@9`.
- **Docker + Docker Compose v2** — only needed for Option B.
- Windows: use Git Bash or WSL for the `cp`/shell-script commands below;
  PowerShell equivalents are given where they differ.

## Option A — UI only, sample data, no backend

Fastest way to look at the app. No Docker, no `.env`.

```bash
pnpm install
cd frontend
pnpm dev
```

Open **http://localhost:5173**. Every screen renders from
`src/lib/*.mock.ts` — no backend required, no login. This is the default:
the app treats `VITE_USE_MOCKS` as `true` unless it's explicitly set to
`'false'` (see `frontend/src/App.tsx` / `src/lib/api.ts`).

## Option B — Full stack (Docker)

Runs Postgres, Redis, all 13 backend services, and the frontend behind
nginx, talking to each other for real.

```bash
cp .env.example .env
```

The stack boots fine with the values already in `.env.example` — `NODE_ENV`
defaults to `development`, so the production-only checks below don't run.
Set real values anyway if you want realistic behavior:

- **`AUTH_JWT_SECRET`** — HS256 secret every service verifies tokens
  against. Only _required_ to change in production (services refuse to
  boot on the default secret when `NODE_ENV=production`, or with any
  secret under 32 characters — see
  `backend/packages/shared/src/http/index.ts`). Generate one:
  ```bash
  # bash
  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
  ```
  ```powershell
  # PowerShell
  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
  ```
- **`AICC_CREDENTIAL_KEYS`** — AES-256-GCM keyring kubernetes-service uses
  to encrypt stored cluster credentials (`v1:<base64-32-bytes>`). Unset =
  plaintext storage with a one-time warning in dev; a production boot
  without it refuses to start (`backend/services/kubernetes/src/config.ts`).
  Same generation command as above, prefixed with a key id:
  ```bash
  echo "v1:$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")"
  ```

Then bring the stack up:

```bash
docker compose up -d --build
```

Check health:

```bash
docker compose ps
curl http://localhost:3001/healthz
```

(Only `postgres` and `redis` have Docker-level healthchecks; the app
services will show as `running` — `/healthz` is the real check. Every
service exposes `/healthz` and `/readyz`.)

Frontend: **http://localhost:5173**.

Observability (Prometheus/Grafana/Loki/Alertmanager/OTel — off by
default):

```bash
docker compose --profile observability up -d
```

- Grafana: **http://localhost:3011** (`admin` / `admin`, set via
  `GF_SECURITY_ADMIN_PASSWORD` in `docker-compose.yml`)
- Prometheus: **http://localhost:9090**
- Alertmanager: **http://localhost:9093**

`make up` / `make down` are shortcuts for `docker compose up -d` /
`docker compose down` (core services only, no observability profile).

## Logging in

The compose stack's `.env` has `NODE_ENV=development` by default, so
auth-service registers its password-less **dev-login** route
(`POST /v1/auth/dev-login`, disabled whenever `NODE_ENV=production`).

The frontend's login screen (shown automatically once `VITE_USE_MOCKS=false`
and you have no token — true for the compose build) just asks for an email
and posts it there. Use the one seeded user:

- **Email**: `admin@aicc.local`
- **Tenant**: `00000000-0000-4000-8000-000000000000` (role `platform_admin`)

(seeded in `backend/services/auth/src/services/user.repository.ts`, in
memory — resets if auth-service restarts.)

`AUTH_DEV_BYPASS=false` in the root `.env.example` — that's a _separate_
knob (trusting `x-tenant-id`/`x-user-id` headers instead of a verified JWT)
and is unrelated to whether dev-login itself is available; the compose
stack keeps it off so requests exercise real JWT verification.

If you see a **"Degraded: showing sample data for N endpoint(s)"** banner:
a real API call failed and the page fell back to mock data instead of
crashing (`src/lib/api.ts`'s `apiHealth`). Check
`docker compose logs <service>` for the failing service.

## Tour

Main sidebar (all wired to real routes):

| Screen                                                | Backed by                                          |
| ----------------------------------------------------- | -------------------------------------------------- |
| Dashboard (`/`)                                       | live once other pages have data; otherwise mock    |
| Assets (`/assets`)                                    | security-service `/v1/assets`                      |
| Incidents (`/incidents`)                              | incident-service `/v1/incidents`                   |
| Vulnerabilities (`/vulnerabilities`)                  | **mock-only** — no backend route yet               |
| SBOM (`/sbom`)                                        | **mock-only** — no components-listing endpoint yet |
| Compliance (`/compliance`)                            | compliance-service `/v1/controls`                  |
| Integrations (`/integrations`)                        | integration-service `/v1/integrations`             |
| Settings (`/settings`)                                | auth-service `/v1/users` (partial)                 |
| Infrastructure Overview (`/infrastructure`)           | kubernetes-service, k8s-health-service             |
| Cluster/Namespace/Workload Explorer                   | kubernetes-service `/v1/kubernetes/*`              |
| Runtime Security (`/infrastructure/runtime-security`) | runtime-security-service                           |
| Topology (`/infrastructure/topology`)                 | topology-service `/v1/topology`                    |
| Cost Intelligence (`/infrastructure/cost`)            | cost-intelligence-service `/v1/cost`               |
| Infrastructure Health/Incidents                       | k8s-health-service, incident-service               |

`AICC_DEMO_SEED=true` (on by default in `docker-compose.yml`) makes
security-, incident-, compliance-, and integration-service insert a small
deterministic fixture set into the demo tenant on boot, so Assets/
Incidents/Compliance/Integrations show real (seeded) rows instead of an
empty state the first time you log in. SBOM and the security-score/
vuln-timeline/risk-heatmap/graph widgets on the Dashboard are still
mock-only regardless (see
[`frontend/README.md`](../frontend/README.md#endpoints-with-no-backend-route-yet-mock-only)).

## Running locally without Docker for development

Run individual services with `pnpm --filter <pkg> dev` (each is
`tsx watch`, no build step) plus the frontend dev server:

```bash
pnpm --filter @aicc/auth-service dev
pnpm --filter @aicc/security-service dev
pnpm --filter @aicc/incident-service dev
cd frontend && pnpm dev   # VITE_USE_MOCKS=false in frontend/.env to hit these
```

No `PORT` env var needed — each service's built-in default (see
`backend/packages/shared/src/http/index.ts`'s `defaultPort()`) already
matches what `vite`'s dev proxy (`frontend/proxy-table.mjs`) expects: auth
3001, agent 3002, security 3003, incident 3004, compliance 3005,
integration 3006, kubernetes 4006, k8s-health 4007, runtime-security 4008,
inventory 4009, cost-intelligence 4010, topology 4011, reporting 4012. Set
`PORT` only to override one:

```bash
PORT=3999 pnpm --filter @aicc/auth-service dev
```

```powershell
$env:PORT=3999; pnpm --filter @aicc/auth-service dev
```

`AUTH_DEV_BYPASS` defaults to `true` whenever `NODE_ENV` isn't
`production` (`backend/packages/shared/src/http/index.ts`), so a bare
`pnpm --filter <svc> dev` accepts `x-tenant-id`/`x-user-id` headers with no
token — useful for `curl`, not wired into the frontend's dev-login flow.

## Troubleshooting

- **Port already in use** (`3001`, `5173`, `5432`, `6379`, ...): something
  else is bound to it — stop it, or change the port mapping in
  `docker-compose.yml` / the `PORT` env var for standalone dev.
- **Secret rejected in production**: `AUTH_JWT_SECRET must be at least 32
characters in production` or `...must be set to a non-default value in
production` — only triggers when `NODE_ENV=production`; set a real
  32+ byte secret (see Option B above).
- **`AICC_CREDENTIAL_KEYS must be set in production`** — kubernetes-service
  refuses to boot with `NODE_ENV=production` and no keyring configured.
- **Login fails / no dev-login route**: check `NODE_ENV` — dev-login is
  never registered when it's `production` (auth-service logs `dev-login
route disabled` on boot).
- **A page shows sample data instead of real rows**: check
  `docker compose logs <service>` — `get<T>()` in `src/lib/api.ts` falls
  back to mocks on any network error or non-2xx response.
- **Windows line endings in `.env`**: if you edited `.env` with a Windows
  editor and a service rejects a value unexpectedly, re-save it with LF
  line endings.

## See also

- [`README.md`](../README.md) — project overview.
- [`frontend/README.md`](../frontend/README.md) — frontend architecture,
  proxy table, mock-only endpoints.
- [`docs/architecture/`](./architecture/) — system design, ADRs.
