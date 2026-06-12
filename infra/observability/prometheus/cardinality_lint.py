#!/usr/bin/env python3
"""
Prometheus Cardinality Lint
============================
Pre-commit / CI gate. Reads a Prometheus recording/alert rule file and rejects
any recording rule whose label combinations could exceed the cardinality
budget defined in docs/observability/monitoring-architecture.md §4.3.

Usage:
    python cardinality_lint.py <rule_file.yml> [<rule_file2.yml> ...]

Exit codes:
    0  OK
    1  Budget violation
    2  Usage / parse error
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with `pip install pyyaml`.", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Budget table — must mirror docs/observability/monitoring-architecture.md §4.3
# ---------------------------------------------------------------------------
BUDGETS: dict[str, int] = {
    "http_server_requests":      50_000,
    "agent_task":                10_000,
    "security_findings":          1_000,
    "llm_tokens":                 5_000,
    "_default":                   1_000,
}

# Heuristic estimate of label cardinality per dimension.
LABEL_CARDINALITY: dict[str, int] = {
    "service":        25,    # ~25 services
    "route":          200,   # ~200 distinct routes per service
    "method":         8,
    "status_class":   5,
    "status":         60,
    "agent":          40,
    "task_type":      30,
    "outcome":        5,
    "tenant_id":      50,    # bounded by tenant capacity plan
    "model":          20,
    "scanner":        10,
    "severity":       5,
    "framework":      4,
    "control":        200,
    "decision_type":  20,
    "tool":           50,
    "ecosystem":      10,
    "direction":      2,
}


@dataclass
class Rule:
    file: str
    group: str
    name: str
    record: str | None
    alert: str | None
    expr: str
    labels: dict[str, str]


def iter_rules(paths: Iterable[str]) -> Iterable[Rule]:
    for path in paths:
        with open(path, "r", encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                print(f"ERROR: failed to parse {path}: {exc}", file=sys.stderr)
                sys.exit(2)
        if not doc:
            continue
        groups = doc.get("groups", []) if isinstance(doc, dict) else []
        for group in groups:
            for rule in group.get("rules", []):
                yield Rule(
                    file=path,
                    group=group.get("name", ""),
                    name=rule.get("record") or rule.get("alert", "<unnamed>"),
                    record=rule.get("record"),
                    alert=rule.get("alert"),
                    expr=rule.get("expr", ""),
                    labels=rule.get("labels", {}) or {},
                )


def estimate_cardinality(metric_name: str, group_by: list[str]) -> int:
    """Estimate the number of unique label combinations for a recording rule."""
    total = 1
    for label in group_by:
        total *= LABEL_CARDINALITY.get(label, 10)
    return total


def extract_group_by(expr: str) -> list[str]:
    """Extract `by (label1, label2, ...)` arguments from a PromQL expression."""
    matches = re.findall(r"\bby\s*\(([^)]*)\)", expr, flags=re.IGNORECASE)
    labels: list[str] = []
    for match in matches:
        for raw in match.split(","):
            label = raw.strip()
            if label:
                labels.append(label)
    return labels


def metric_family(metric_name: str) -> str:
    """Reduce a metric name to its 'family' key for budget lookup."""
    name = metric_name.lower()
    for family in BUDGETS:
        if family == "_default":
            continue
        if family in name:
            return family
    return "_default"


def check_rule(rule: Rule) -> list[str]:
    if not rule.record:
        return []   # alert rules use pre-existing series, no new cardinality
    group_by = extract_group_by(rule.expr)
    estimated = estimate_cardinality(rule.record, group_by)
    family = metric_family(rule.record)
    budget = BUDGETS.get(family, BUDGETS["_default"])
    if estimated > budget:
        return [
            f"  {rule.file} :: group={rule.group} record={rule.record}\n"
            f"    by ({', '.join(group_by) or '<none>'}) -> "
            f"~{estimated:,} combinations, budget={budget:,} (family={family})"
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help="Prometheus rule files")
    args = parser.parse_args()

    failures: list[str] = []
    rules = list(iter_rules(args.files))
    if not rules:
        print("No rules found.")
        return 0

    print(f"Checking {len(rules)} rule(s) across {len(args.files)} file(s)...")
    for rule in rules:
        failures.extend(check_rule(rule))

    if failures:
        print("\nCardinality budget violations:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        print(
            f"\n{len(failures)} violation(s). See "
            "docs/observability/monitoring-architecture.md §4.3.",
            file=sys.stderr,
        )
        return 1

    print("OK — all rules within cardinality budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
