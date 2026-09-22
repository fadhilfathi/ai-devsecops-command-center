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

Frontend: <http://localhost:5173> · Grafana: <http://localhost:3011>
(admin/admin) · Prometheus: <http://localhost:9090>.

## Conventions

- Kubernetes manifests use **kustomize** overlays per environment.
- Terraform modules live next to the resource they create.
- No long-lived credentials in this folder. Use a secret manager.
- All resources are tagged with `Project=ai-devsecops-command-center`
  and `Environment=<env>`.
