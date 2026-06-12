# Load tests

k6 scripts that exercise the platform at scale.

```
load/
├── api-baseline.js
├── agent-throughput.js
├── event-bus-burst.js
└── scenarios/
    ├── pr-scan-storm.js
    └── incident-storm.js
```

Run with `k6 run tests/load/api-baseline.js` or via the
[`tests:load`](../../package.json) npm script. CI runs a smoke load profile
on every release.
