# CI scripts

Helper scripts invoked from GitHub Actions.

```
ci/
├── install-deps.sh
├── run-tests.sh
├── run-lint.sh
├── build-services.sh
├── build-frontend.sh
└── publish-image.sh
```

These wrap the underlying `npm`/`pnpm`/`docker` commands and add
deterministic logging, retry, and artifact capture.
