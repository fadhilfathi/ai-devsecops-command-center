# Kubernetes manifests

Helm chart and raw manifests for production deployment. Delivered in **Sprint 3**.

Planned contents:

```
kubernetes/
├── base/                       # Kustomize base
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secret-store.yaml
│   └── kustomization.yaml
├── services/                   # one folder per service
│   ├── auth/
│   ├── agent/
│   ├── security/
│   ├── incident/
│   ├── compliance/
│   └── integration/
├── data/                       # Postgres, Redis
│   ├── postgres/
│   └── redis/
├── ingress/                    # nginx / traefik / gateway-api
├── observability/              # Prometheus, Loki, Grafana, OTel Collector
└── helm/                       # umbrella chart
    └── Chart.yaml
```

The Helm chart will ship in Sprint 3 alongside the production-readiness
milestone. Until then, [`infra/docker/docker-compose.yml`](../../docker/docker-compose.yml)
is the local development story.
