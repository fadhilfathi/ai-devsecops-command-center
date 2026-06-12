# Integration tests

Multi-service tests that exercise the API, the event bus, and the data plane
together. Built on **Testcontainers** (Node) and **docker-compose** for
hermetic, reproducible runs.

```
integration/
├── api/
├── event-bus/
├── agents/
└── security/
```

Each test spins up the services it needs, runs the scenario, asserts on both
the HTTP response and the resulting events, and tears everything down.
