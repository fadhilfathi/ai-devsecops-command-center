# Deploy scripts

Production deployment helpers.

```
deploy/
├── deploy-dev.sh
├── deploy-staging.sh
├── deploy-prod.sh
├── rollback.sh
├── smoke-test.sh
└── canary-promote.sh
```

All scripts are idempotent, log to stdout in JSON, and require explicit
confirmation when targeting `prod`.
