# dependency-intel — Dependency Intelligence Service (S2.3)

> Builds dependency graphs from SBOMs, propagates risk transitively, and
> correlates vulnerabilities from vuln-intel (S2.2). FastAPI service,
> port **4009**.

## Responsibilities

| Capability | Notes |
|---|---|
| Graph construction (direct deps) | from SBOM `components` + `dependencies` blocks (CycloneDX 1.5 / SPDX 2.3 compatible) |
| Graph construction (transitive) | merge multiple SBOMs into a single workspace graph keyed by PURL |
| Vulnerability correlation | call `vuln-intel` (S2.2) to attach findings to nodes |
| Risk propagation | PageRank-style + per-vulnerability inflation; per-node risk = `0.4*local + 0.6*propagated` |
| Reachability hints | mark "direct" vs "transitive" dependencies and propagate direct-flag through the graph |
| "Fix priority" | rank nodes by `(severity, epss, kev, centrality)` |
| Cluster detection | weakly-connected components → "vulnerability clusters" |
| Local store | JSONL graph snapshots (one per SBOM ingest) |

## Data model

```
GraphNode {
  id: "<purl or hash>"          # canonical key
  purl: str
  ecosystem: str
  name: str
  version: str
  is_direct: bool
  is_root: bool                 # is the application itself
  sbom_ids: [str]               # which SBOMs declared this node
  direct_dependents: [str]      # ids of nodes that depend on this one
  findings: [{ cve_id, severity, epss?, kev? }]
  risk_score: float             # 0..100
  fix_priority: int             # 0 = top priority
}

GraphEdge { from, to, kind ("runtime"|"dev"|"optional"|"build"|"test"|"unknown"), scope }
```

The full Pydantic schema lives in
`src/dependency_intel/models/graph.py`.

## Endpoints (REST, JSON)

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/livez`                                    | Liveness |
| `GET`  | `/readyz`                                   | Readiness |
| `GET`  | `/metrics`                                  | Prometheus |
| `POST` | `/dep-intel/graph/build`                    | Build a graph from an SBOM (single or workspace) |
| `GET`  | `/dep-intel/graph/{graph_id}`               | Fetch a stored graph |
| `POST` | `/dep-intel/graph/{graph_id}/correlate`     | Pull vulnerabilities from vuln-intel and attach to nodes |
| `POST` | `/dep-intel/risk/calculate`                 | Re-run risk propagation for a graph |
| `GET`  | `/dep-intel/risk/{graph_id}`                | Get per-node risk + top-N priority list |
| `GET`  | `/dep-intel/clusters/{graph_id}`            | Weakly-connected vulnerability clusters |
| `GET`  | `/dep-intel/graph/{graph_id}/export`        | Export the graph as JSON / GraphML / DOT |

## Configuration (env vars)

| Var | Default | Notes |
|---|---|---|
| `DEP_INTEL_PORT` | `4009` | API port |
| `DEP_INTEL_DATA_DIR` | `./data` | Where graphs are stored |
| `DEP_INTEL_VULN_INTEL_URL` | `http://localhost:4008` | Upstream S2.2 service |
| `DEP_INTEL_RISK_ALPHA` | `0.6` | Propagation weight in `[0,1]` |
| `DEP_INTEL_RISK_DAMPING` | `0.85` | PageRank damping factor |
| `DEP_INTEL_MAX_GRAPH_NODES` | `50000` | Reject graphs larger than this |
| `DEP_INTEL_AUTH_REQUIRED` | `false` | toggle bearer JWT check |

## Local dev

```bash
cd agents/roles/security/dependency-intel
pip install -e ".[dev]"
DEP_INTEL_PORT=4009 python -m dependency_intel
```

## Algorithms in brief

### Risk propagation

Let `R_i` be the local risk of node `i` (sum of severity scores of
vulnerabilities attached to `i` plus an EPSS/KEV bonus). The propagated
risk is computed as the personalised PageRank of the dependency graph
with the local-risk vector as the teleport vector. The final
`risk_score ∈ [0, 100]` is

```
risk_i = alpha * (0.4 * R_i + 0.6 * PageRank_i) + (1 - alpha) * baseline
```

with `alpha = DEP_INTEL_RISK_ALPHA` and `baseline = 5.0`.

### Fix priority

`fix_priority = round(100 * risk_score + 25 * kev_bonus + 10 * epss_bonus)`.

### Cluster detection

Connected components of the bipartite (package, vulnerability) graph.
We group packages into "vulnerability clusters" when at least 50 % of
their direct neighbours share a vulnerability.
