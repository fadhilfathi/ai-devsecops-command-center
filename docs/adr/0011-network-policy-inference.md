# 0011 — Network-policy inference and mesh detection

Status: accepted
Date: 2026-09-22

## Context

Sprint 5's topology engine draws `routes_to`/`calls`/`selects` edges
between services, workloads, and pods, but says nothing about whether
that traffic is actually permitted by the cluster's `NetworkPolicy`
objects, or whether it flows through a service-mesh sidecar.

## Decision

- **matchLabels-only.** `NetworkPolicy.podSelector` and peer selectors
  model `matchLabels` (`Record<string, string>`) only —
  `matchExpressions` is not represented. A selector we can't evaluate
  is treated as non-matching rather than guessed at.
- **Ingress-only evaluation.** `inferNetworkPolicy()` only reasons
  about `ingress` rules (does traffic into the target's pods get
  admitted). `egress` is modelled in the schema (so a future pass can
  read it) but never evaluated — most lateral-movement questions the
  topology view answers are "can X reach Y", which is an ingress
  question from Y's side.
- **Peer semantics follow Kubernetes.** A `from` entry with only
  `podSelector` matches pods in the policy's own namespace; with only
  `namespaceSelector` it matches every pod in the selected namespaces;
  with both it is the intersection (AND). Separate entries are OR-ed.
- **`ipBlock` peers never match** an in-graph edge: there is no
  synthetic source IP for a workload/pod node to compare against a
  CIDR. This under-approximates `allowed` in favour of `denied`, which
  is the safer default for a security-facing view.
- **HTTP inventory client vs fixture.** `topology-service`'s
  `InventoryClient` fixture stays the in-process default (no network
  dependency for local dev / CI). When `KUBERNETES_SERVICE_URL` is
  set, a second implementation calls the kubernetes-service inventory
  routes over `fetch` and validates every response against the
  `@aicc/models` Zod schemas, so a shape drift between services fails
  loudly instead of shipping malformed data into the engine.
- **Mesh detection is a label/name heuristic**: a namespace injection
  label (`istio-injection=enabled`, `linkerd.io/inject=enabled`) or a
  sidecar container named `istio-proxy`/`linkerd-proxy` tags the
  node's `metadata.mesh`. It does not read `MeshConfig`/CRDs.

## Consequences

- `TopologyGraph.networkPolicySummary` and per-edge
  `metadata.networkPolicy` are only populated by `fullGraph()`; the
  Service Map and Application Graph views do not carry the
  annotation. Add it there if the frontend needs it on those views.
- A `NetworkPolicy` using `matchExpressions` degrades silently to "no
  match" for that selector — worth a follow-up warning if operators
  start hitting it in practice.
