# Setup scripts

One-shot scripts to bootstrap a fresh checkout.

```
setup/
├── bootstrap.sh       # installs toolchain, pre-commit hooks
├── bootstrap.ps1      # Windows variant
├── generate-certs.sh  # local dev TLS certs
└── seed-fixtures.sh   # load demo data for local dev
```

Run `make setup` after cloning to get a working local environment in under
five minutes.
