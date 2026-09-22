# 0012 — Cost utilisation from Prometheus

Status: accepted
Date: 2026-09-22

## Context

Sprint 4's cost engine sized recommendations off _deterministic
synthetic_ utilisation values (a fixed 0.4/0.6 CPU and 0.5/0.7 memory
p50/p95 for every workload) because no metrics backend was wired.
The docker-compose stack now runs Prometheus with a kubelet/cAdvisor
scrape job exposing `container_cpu_usage_seconds_total` and
`container_memory_working_set_bytes` labelled by `namespace`, `pod`,
`container`.

## Decision

- **`UtilisationSource` abstraction.** The cost engine stays
  metrics-agnostic — it takes a `utilisation` map (p50/p95 ratios per
  workload id) from the caller. Two implementations:
  `buildSyntheticUtilisationSource()` (unchanged Sprint 4 behaviour)
  and `buildPrometheusUtilisationSource()`. `cost-intelligence`
  selects the Prometheus source when `PROMETHEUS_URL` is set, else
  synthetic.
- **Pod → workload mapping.** Pods are matched to a workload by
  `namespace` + `ownerName === workload.name`. If the inventory
  snapshot has no pods for a workload (e.g. fixture data, or the pod
  list hasn't synced yet), we fall back to a `^<workload-name>-`
  regex against the `pod` label — the standard ReplicaSet/StatefulSet
  pod-naming convention. All workload/pod names are regex-escaped
  before being interpolated into PromQL.
- **One query per metric/quantile per namespace, not per workload.**
  Pods across every workload in a namespace are matched with a single
  `pod=~"a|b|c"` regex and grouped `sum by (pod)`; results are then
  summed back to their owning workload client-side. This keeps the
  query count at 4 per namespace regardless of workload count.
- **`quantile_over_time` over the analysis window.** CPU uses
  `quantile_over_time(0.5|0.95, sum by (pod) (rate(container_cpu_usage_seconds_total{...}[5m]))[window:5m])`;
  memory uses the same shape without the `rate()` (working-set bytes
  is already a gauge). `window` is `windowEnd - windowStart` rounded
  to whole minutes, floored at 5m.
- **Ratio math.** CPU ratio = summed CPU cores / (`cpuRequestsMillicores`/1000
  × `podCount`); memory ratio = summed bytes / (`memoryRequestsBytes` ×
  `podCount`), where `podCount` is the number of pods that actually
  matched the workload's regex in the Prometheus response — the request
  is per-pod, so it must scale with pod count before comparing to a
  cluster-wide summed usage. When the pod-name regex fell back to the
  `^<workload-name>-` prefix (no owned pods known from inventory),
  `podCount` instead uses `workload.replicas.ready` (falling back to
  `desired`) since the prefix match can't be trusted to enumerate every
  replica. Ratios are clamped to `[0, 5]`. A workload with a zero
  request, or no matching series in the Prometheus response, is left
  out of the map entirely — the engine's built-in defaults apply
  instead of a false zero.
- **PromQL injection.** Every label value interpolated into a query
  (`namespace`, pod names, the workload-name regex fallback) is passed
  through `promQuote()`, which strips control characters and escapes
  `\` and `"` per PromQL string-literal rules. Regex values are
  `escapeRegex()`'d first (to become valid regex syntax) and then
  `promQuote()`'d (so the PromQL string literal round-trips back to
  that exact regex) — untrusted namespace/pod/workload names from
  inventory data can never break out of the label matcher.
- **Degrade, never fail.** A non-2xx response, `status != "success"`,
  a network error, or a 10s timeout (`AbortSignal.timeout`) is logged
  as a warning and treated as "no data" for that query — the request
  never fails because Prometheus is unreachable.
- **`utilisationSource` provenance.** `UtilisationSource.fetch()`
  returns `{ utilisation, kind }`; the Prometheus source reports
  `kind: 'synthetic'` whenever it degraded to an empty map (no data or
  an error), so `CostAnalysis.utilisationSource` (`'prometheus' |
'synthetic'`) always reflects what was actually used for that
  request, not just whether `PROMETHEUS_URL` is configured.
- **HTTP inventory client for cost-intelligence.** Mirrors ADR 0009's
  pattern: the fixture provider stays the in-process default; setting
  `KUBERNETES_SERVICE_URL` swaps in an HTTP provider that calls
  kubernetes-service and Zod-validates every response.

## Consequences

- Utilisation accuracy now depends on cAdvisor's per-container metrics
  reaching Prometheus with correct `namespace`/`pod`/`container`
  labels — a relabeling mismatch silently degrades a workload back to
  the engine's static defaults rather than erroring.
- The window is capped at 5-minute resolution regardless of the
  requested analysis window; sub-5-minute windows are not meaningfully
  supported by the `[window:5m]` subquery step.
