"""SBOM analyzer — derives stats from a stored SBOM.

The analyzer takes the raw CycloneDX JSON of a stored SBOM and
returns:

* ``components`` — total component count
* ``transitive_depth`` — longest path in the dependency graph
* ``ecosystems`` — distinct ecosystem names (``npm``, ``pypi``, …)
* ``license_breakdown`` — `{license_id: count}` map
* ``total_size_bytes`` — sum of any byte-size hints on components
  (CycloneDX's ``properties`` array is the most common carrier;
  we look for ``size``, ``installSize``, ``downloadSize`` keys).

The same analyzer is used by:

* ``POST /sbom/analyze`` (HTTP API)
* ``python -m sbom_pipeline analyze --sbom-id <id>`` (CLI)
* S2.3 (dependency-intel) — to bootstrap the graph
* S2.9 (compliance auto-mapping) — for license risk surface area
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sbom_pipeline.models import Sbom, ecosystem_from_purl

logger = logging.getLogger("sbom_pipeline.analyzer")


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def analyze(sbom: Sbom) -> Dict[str, Any]:
    """Return the full analysis payload for the :class:`Sbom`."""
    return {
        "components": len(sbom.components),
        "transitive_depth": _transitive_depth(sbom),
        "ecosystems": sorted(_ecosystems(sbom)),
        "license_breakdown": _license_breakdown(sbom),
        "total_size_bytes": _total_size_bytes(sbom),
    }


# ---------------------------------------------------------------------------
# Individual stat helpers
# ---------------------------------------------------------------------------


def _transitive_depth(sbom: Sbom) -> int:
    """Longest path in the dependency graph.

    A leaf (no outgoing edges) has depth 0. A component that depends
    on a leaf has depth 1. We use memoised DFS to avoid recomputation
    in cyclic graphs.

    **Cycle policy.** If the dependency graph contains a cycle, the
    longest-path value is not well-defined (a cycle has no "longest"
    path — paths are unbounded). The security team asked for a
    well-defined value that downstream code can bucket on, so we
    collapse *any* detected cycle to depth 0. The presence of the
    cycle is signalled to the caller via the OTel span event
    ``dependency.cycle`` (set by the API layer).
    """
    graph: Dict[str, List[str]] = {}
    for dep in sbom.dependencies:
        graph[dep.ref] = list(dep.dependsOn)
    # Add isolated components as 0-depth leaves.
    for c in sbom.components:
        graph.setdefault(c.bom_ref, [])

    memo: Dict[str, int] = {}
    visiting: Set[str] = set()
    cycle_detected: List[bool] = [False]

    def depth(node: str) -> int:
        if node in memo:
            return memo[node]
        if node in visiting:
            # Cycle — flag it and return a sentinel of 0 so the
            # recursion terminates.
            cycle_detected[0] = True
            return 0
        visiting.add(node)
        children = graph.get(node) or []
        d = 0 if not children else 1 + max(depth(c) for c in children)
        visiting.discard(node)
        memo[node] = d
        return d

    if not graph:
        return 0
    result = max(depth(n) for n in graph)
    return 0 if cycle_detected[0] else result


def _ecosystems(sbom: Sbom) -> Set[str]:
    ecosystems: Set[str] = set()
    for c in sbom.components:
        eco = ecosystem_from_purl(c.purl)
        if eco.value != "unknown":
            ecosystems.add(eco.value)
    return ecosystems


def _license_breakdown(sbom: Sbom) -> Dict[str, int]:
    """Count components per license id / name / expression.

    Unknown licenses are bucketed under ``"unknown"`` so the
    dashboard has a single key for "license not declared".
    """
    counts: Counter = Counter()
    for c in sbom.components:
        if not c.licenses:
            counts["unknown"] += 1
            continue
        for lic in c.licenses:
            if lic.expression:
                counts[lic.expression] += 1
            elif lic.license:
                key = (
                    lic.license.get("id")
                    or lic.license.get("name")
                    or "unknown"
                )
                counts[str(key)] += 1
            else:
                counts["unknown"] += 1
    return dict(counts.most_common())


_SIZE_KEYS = ("size", "installSize", "downloadSize", "size_bytes", "sizeBytes")
_SIZE_RE = re.compile(r"(\d+(?:\.\d+)?[\d_]*)\s*(b|kb|mb|gb)?", re.IGNORECASE)
_SIZE_UNITS = {
    None: 1,
    "b": 1,
    "kb": 1024,
    "mb": 1024 ** 2,
    "gb": 1024 ** 3,
}


# ---------------------------------------------------------------------------
# Cardinality-safe size bucketing
# ---------------------------------------------------------------------------

#: Boundary table for :func:`size_bucket`. Four buckets keep the
#: metric label ``sbom_size_bucket`` well within the SRE cardinality
#: budget (see ``docs/observability/slos-security-stack.md``).
_SIZE_BUCKETS: Tuple[Tuple[int, str], ...] = (
    (100, "small"),
    (1_000, "medium"),
    (10_000, "large"),
)


def size_bucket(n: int) -> str:
    """Map a component count to a low-cardinality bucket.

    Boundaries (locked with S2.7 / SRE):

    * ``n < 100``        → ``"small"``
    * ``100 ≤ n < 1k``   → ``"medium"``
    * ``1k ≤ n < 10k``   → ``"large"``
    * ``n ≥ 10k``        → ``"xlarge"``

    Negative values fall into ``"small"`` — a defensive choice for
    malformed inputs; the analyzer never produces negatives.
    """
    if n < 0:
        return "small"
    for ceiling, label in _SIZE_BUCKETS:
        if n < ceiling:
            return label
    return "xlarge"


def _total_size_bytes(sbom: Sbom) -> int:
    """Sum size hints found in component properties / hashes.

    The function is deliberately permissive: we look in:

    * ``component.properties[]`` (CycloneDX's recommended location)
    * ``component.hashes[]`` (rare but seen in the wild — the hash
      itself is not a size, so we ignore it; this branch is a
      no-op by design)

    If no size hints are present, the total is 0.
    """
    total = 0
    for c in sbom.components:
        # Properties is a list of {name, value} dicts per CycloneDX.
        props = c.model_extra or {}
        # Pydantic 2 keeps ``extra`` here when ``extra="allow"``.
        raw_props = props.get("properties") or []
        for p in raw_props:
            if not isinstance(p, dict):
                continue
            if p.get("name") in _SIZE_KEYS:
                total += _parse_size(str(p.get("value", "")))
    return total


def _parse_size(value: str) -> int:
    """Parse a human size string (``"12 kb"``, ``"1.5 mb"``, ``"1024"``) to bytes.

    Supports:

    * decimals (``"1.5 mb"`` → ``1572864``)
    * underscores as thousand separators (``"1_000 kb"`` → ``1024000``)
    * case-insensitive unit suffixes (``"KB"``, ``"Gb"``)
    * plain numbers (``"1024"`` → ``1024``)
    """
    m = _SIZE_RE.search(value)
    if not m:
        return 0
    number_str = m.group(1).replace("_", "")
    number = float(number_str) if "." in number_str else int(number_str)
    unit = (m.group(2) or "").lower() or None
    return int(number * _SIZE_UNITS.get(unit, 1))
