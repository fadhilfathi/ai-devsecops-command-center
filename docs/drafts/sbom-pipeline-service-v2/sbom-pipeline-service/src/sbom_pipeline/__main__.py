"""Allow ``python -m sbom_pipeline`` to dispatch to the CLI."""

from sbom_pipeline.cli import main

raise SystemExit(main())
