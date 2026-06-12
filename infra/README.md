# Infrastructure

> Kubernetes manifests, Terraform modules, and container images for
> staging and production deployments.

```
infra/
├── docker/         # shared Dockerfiles and base images
├── kubernetes/     # k8s manifests, kustomize overlays, Helm charts
├── terraform/      # IaC for cloud resources (DBs, networking, IAM)
└── observability/  # Prometheus, Grafana, Loki, OTel configs
```

## Local dev

`docker-compose.yml` at the repo root is the local stack. The configs in
this folder are for non-local environments.

## Conventions

- Kubernetes manifests use **kustomize** overlays per environment.
- Terraform modules live next to the resource they create.
- No long-lived credentials in this folder. Use a secret manager.
- All resources are tagged with `Project=ai-devsecops-command-center`
  and `Environment=<env>`.
