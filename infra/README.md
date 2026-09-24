# Infrastructure

> Kubernetes manifests, Terraform modules, and container images for
> staging and production deployments.

```
infra/
├── docker/         # Postgres init scripts for the local stack
├── kubernetes/     # k8s manifests, kustomize overlays, Helm charts
├── terraform/      # IaC for cloud resources (DBs, networking, IAM)
└── observability/  # Prometheus, Grafana, Loki, OTel configs
```

## Run the stack

`docker-compose.yml` at the repo root is the local stack (Postgres, Redis,
all 13 backend services, the frontend, and the observability toolchain).
The configs in this folder are for non-local environments.

```
cp .env.example .env
docker compose up --build
```

The observability toolchain (Prometheus, Alertmanager, Grafana, Loki,
OTel collector) is behind a compose `observability` profile — it's not
needed for the app to run, so the default `up` skips it:

```
docker compose --profile observability up --build
```

Frontend: <http://localhost:5173> · Grafana: <http://localhost:3011>
(admin/admin) · Prometheus: <http://localhost:9090>.

`scripts/e2e-smoke.mjs` exercises the running stack end to end (health,
one authenticated route per service, negative-auth, the frontend proxy)
— see `.github/workflows/e2e.yml`, which runs it against a freshly
built compose stack (without the observability profile) on every push
to `main` and weekly.

## Conventions

- Kubernetes manifests use **kustomize** overlays per environment.
- Terraform modules live next to the resource they create.
- No long-lived credentials in this folder. Use a secret manager.
- All resources are tagged with `Project=ai-devsecops-command-center`
  and `Environment=<env>`.
