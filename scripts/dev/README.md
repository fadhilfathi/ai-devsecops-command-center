# Dev scripts

Local development helpers, invoked from the Makefile.

```
dev/
├── start-data-plane.sh
├── start-backend.sh
├── start-frontend.sh
├── seed-db.sh
├── reset-db.sh
├── open-swagger.sh
└── tail-logs.sh
```

Cross-platform note: on Windows these are mirrored as PowerShell scripts in
`scripts/dev/*.ps1` and exposed via the `Makefile` using `pwsh -File`.
