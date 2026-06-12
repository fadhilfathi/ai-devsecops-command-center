# Terraform landing zone

Infrastructure-as-Code for the production cloud landing zone. Delivered in
**Sprint 3**.

Planned contents:

```
terraform/
├── modules/
│   ├── network/        # VPC, subnets, NAT, SG
│   ├── eks/            # Managed Kubernetes (or AKS/GKE equivalent)
│   ├── rds/            # Managed Postgres
│   ├── elasticache/    # Managed Redis
│   ├── s3/             # Object store for evidence + SBOMs
│   ├── kms/            # Per-tenant encryption keys
│   ├── irsa/           # IAM roles for service accounts
│   └── observability/  # Managed Grafana / Prometheus / Loki
├── envs/
│   ├── dev/
│   ├── staging/
│   └── prod/
└── README.md
```

Multi-cloud abstraction will live in `modules/`. The first cloud target is
AWS; GCP and Azure providers will follow in subsequent sprints.
