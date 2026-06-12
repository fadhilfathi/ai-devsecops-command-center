# E2E tests

End-to-end suites that exercise the full stack from the browser down to the
event bus. Implemented with **Playwright**.

```
e2e/
├── pages/             # Page Object Model
├── fixtures/          # deterministic seed data
├── specs/
│   ├── auth.spec.ts
│   ├── dashboard.spec.ts
│   ├── vulnerabilities.spec.ts
│   ├── incidents.spec.ts
│   ├── compliance.spec.ts
│   └── integrations.spec.ts
└── playwright.config.ts
```

Run via `npm run test:e2e` from the repository root. CI runs them against a
freshly built image on every PR.
