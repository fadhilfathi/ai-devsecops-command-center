# Backend services

> The six backend services of the AI-DevSecOps Command Center. Each is
> an independent deployable unit, sharing types, contracts, and
> observability through `backend/packages/shared/` and `backend/common/observability/`.

```
backend/
├── services/
│   ├── auth/         # port 3001  - identity, RBAC, sessions
│   ├── agent/        # port 3002  - agent runtime, dispatch, memory
│   ├── security/     # port 3003  - assets, vulnerabilities, SBOM
│   ├── incident/     # port 3004  - incident lifecycle, correlation
│   ├── compliance/   # port 3005  - control mapping, evidence
│   └── integration/  # port 3006  - external system adapters
└── shared/           # cross-cutting: contracts, events, middleware, types, utils
```

Each service is a self-contained Node.js + TypeScript project using
**Fastify 4**. See [`/docs/adr/0006-monorepo-pnpm.md`](../../docs/adr/0006-monorepo-pnpm.md) and the package layout.

## Common structure

```
backend/services/<name>/
├── src/
│   ├── index.ts        # entrypoint (boots the server)
│   ├── server.ts       # builds the Fastify instance
│   ├── config.ts       # env parsing
│   ├── plugins/        # Fastify plugins
│   ├── routes/         # HTTP routes
│   ├── services/       # business logic
│   ├── repositories/   # data access
│   ├── events/         # event bus producers/consumers
│   └── types.ts        # local types
├── test/
│   ├── unit/
│   └── integration/
├── Dockerfile
├── package.json
├── tsconfig.json
└── README.md
```

## Running a service

```bash
pnpm --filter @aicc/auth-service dev
# or
make dev-auth
```

## See also

- [`/docs/architecture/system-architecture.md`](../../docs/architecture/system-architecture.md)
- [`/docs/architecture/event-bus.md`](../../docs/architecture/event-bus.md)
- [`/docs/architecture/security-model.md`](../../docs/architecture/security-model.md)
