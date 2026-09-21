# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### 0.1.1 (2026-09-21)


### Features

* **cost:** add Kubernetes cost intelligence service (S4-EPIC-5) ([ff9df92](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/ff9df92a182ff5eaa6058190dd6ef911207b1666))
* **frontend:** add Sprint 4 infrastructure dashboard modules (S4-EPIC-8) ([b964010](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/b9640100be7f3db272b11c2eccbecc7e84c5193c))
* **incident:** extend correlation engine for Kubernetes + CI/CD (S4-EPIC-7) ([471595b](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/471595b3f7a67dd3227f8ee4d71ed5e0cfecd43c))
* **inventory:** add infrastructure inventory engine service (S4-EPIC-4) ([6f8d9e0](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/6f8d9e091905da9f4c14e1bc0d3d692c0a0c6957))
* **k8s-health:** add K8s health engine service (S4-EPIC-2) ([df8be10](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/df8be10f3b45ee043c99d8ded94f25df628363f5))
* **kubernetes:** add kubernetes integration service (S4-EPIC-1) ([f9cb1e1](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/f9cb1e184cecd8152b969c1d88671a0723114552))
* **models:** add Sprint 4 infrastructure model layer (S4-EPIC-9) ([a5c5316](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/a5c5316bc7f239e69bb4bf2e68aa935729689086))
* **o-3:** event-bus wire format versioning + S2.10 compliance events refactor ([2cc60bf](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/2cc60bf871da9c742aefa5db13df954133e7a1f0))
* **observability,frontend,memory:** Sprint 2 service integration + UI + memory ([5ae2dc1](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/5ae2dc1ef79b08550f2af1025425f355e52cdf5c))
* **observability:** Python OTel/structlog/prometheus shared module (S2.7) ([8af9731](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/8af9731350c64edc71be2792099fd207ff84c2d5))
* **reporting:** add infrastructure reporting service (S4-EPIC-10) ([08590a7](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/08590a7e4282f0fa89fe30c21efc9beeff73915f))
* **runtime-security:** add runtime security intelligence service (S4-EPIC-3) ([79f89f5](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/79f89f5373218cdf5f40064ac0e53193ff863be6))
* **s2.7+s2.8:** SLO doc amendments B1-B4 + C1-C3 + D1-D5 + S2.8 control alerts (T-02/T-03/T-04/T-05/T-08/T-09) ([5773534](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/57735343facd2e7acea0add9fea32efe83bab282))
* **s2.7:** security-service :4003 prom-client instrumentation ([863e3d5](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/863e3d5041e69d07bcec99928a3f80aea061cdfd))
* **s2.7:** TypeScript observability shim + metrics-spec catalog ([b2d197f](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/b2d197ff8d7a8cdc52f55e5063a00487778c7bdb))
* **s2.8+o-3:** event-log subscribes to SCAN_TOPIC + audit_log schema adds service + retention_class ([00eca38](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/00eca38d6147480979f65e9cbc3fb539e1fe671d))
* **s2.8:** compliance audit wrappers + vulnerability model tenant_id_hash + syft CLI v1 → current fix ([baa46c6](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/baa46c63df72233ba5e79383fa90cf26951936cd))
* **s2.8:** S2.8 mitigation implementations — audit, consensus, validators, LLM scorer, projection boundary ([423dc6f](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/423dc6f076d9691deda7775df540afd33b00b3ae))
* **s2.8:** security-stack threat model + mitigations doc ([e2181b8](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/e2181b85d549a854296c475f4c1c77add2611197))
* **security:** 5-endpoint security API + compliance control-mapper (S2.5+S2.9) ([c46cba0](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/c46cba0981bfdcb27ecef3c5609f30b2fa09fbf5))
* **security:** shared security data models (S2.4) ([c84c30d](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/c84c30de2ed9d6304bb0161b15fd3470e97cd738))
* **security:** Syft-wrapped SBOM pipeline + dependency intelligence (S2.1+S2.3) ([33eb653](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/33eb653c69a6aa85ff2ea77b4f3c8ab8eda964a2))
* **sprint-1:** initial multi-agent AI DevSecOps Command Center skeleton ([269aa9e](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/269aa9e82d4fa237a5cfd6e035a00e21fa2ed171))
* **sprint-2-final:** in-flight cleanup — VulnKind/VulnSeverity fix, contract test infra, Round 6 SLO, event-bus §12 ([3e241f6](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/3e241f6a974e1670f2567f54104f565c5a72e378))
* **sprint-2-inflight:** O-3.7 wire format alignment — fingerprint algorithm/format, consensus_sources, pre-actionable hint, S2.8 T-03 signal, spec metric rename ([2e85a86](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/2e85a8618d2327b81fb46d4617132e0894d1719f))
* **sprint-2-inflight:** SBOM agent metrics, vuln-intel validators/audit/LLM, audit emission SLO+alerts, VulnKind Zod-inferred, CODEOWNERS ([a81f2a9](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/a81f2a9ab71a95bc91f8c62844ec156e30c78409))
* **sprint-2.8:** SSRF defense (T-07) for sbom-generator dev_input targets ([02e2b43](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/02e2b43e593691d1e07ab42e9c80f0cc5be33dc0))
* **sprint-2.8:** wire SSRF defense into request validation (T-07 final wire-up) ([66e1a66](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/66e1a669fffb182b13904953a0fca13c90a15367))
* **sprint-2.8:** wire SsrfConfig into Settings (T-07 follow-up) + memory 89-test count ([a237c9b](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/a237c9bc5942087aa23caef23fc3b5c4669d1bf6))
* **topology:** add topology engine service (S4-EPIC-6) ([2afebec](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/2afebecc960ba5fe1cf032ae26c20e687d024325))


### Bug Fixes

* **s2.3:** dep-intel hardening — structured logging, metrics registry, PageRank rewrite with graph reversal and max-scaling ([219c6ab](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/219c6abdbf9eda82ecdf128ce9d287a162cc6ce8))
* **s2.8:** syft lazy binary resolution + vuln-intel app.py wire S2.8 modules + metrics-spec v1.0.3 round 5 ([93c5526](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/93c55263cadb38aae2abf6cc3c0acb5bf3232cf8))
* **sprint-2.5:** SBOM v1 wire format drift fix (O-3.7 schema alignment) ([b7413e3](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/b7413e3a2ceb934f13bc6987f454bc8fbb24053a))
* **sprint-2.7-followup:** SBOM agent 5-bucket scheme → D7 LOCKED (xs/small/medium/large/xlarge) ([a20f59a](https://github.com/fadhilfathi/ai-devsecops-command-center/commit/a20f59a52e5b3ffeae02783dee391e365f388222))

## [0.1.0] - YYYY-MM-DD

### Added
- …

### Changed
- …

### Fixed
- …
-->
