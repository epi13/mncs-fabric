#!/usr/bin/env python3
"""Resolve the example workload requirements against the local machine.

Demonstrates pre-execution capability resolution end to end: the local
environment is discovered (never hand-written), the example queries are
loaded, and each resolves to eligible/selected or NO_ELIGIBLE_WORKER
with machine-readable reasons.

Run from the repository root:
    python3 examples/capability/resolve_example.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mncs_fabric.capability_resolution import (  # noqa: E402
    CapabilityQuery,
    WorkerSnapshot,
    default_policy,
    resolve_fleet,
)
from mncs_fabric.node import collect_node_capabilities  # noqa: E402
from mncs_fabric.platform_probe import env_from_node  # noqa: E402

EXAMPLES = Path(__file__).resolve().parent / "workload-requirements.example.json"


def main() -> int:
    node = collect_node_capabilities("example-local-worker")
    from mncs_fabric.node import capability_names

    local = WorkerSnapshot(
        worker_id="example-local-worker",
        capabilities=frozenset(capability_names(node)),
        env=env_from_node(node),
        policy=default_policy(),
        liveness="AVAILABLE",
        capability_age_seconds=None,
        provenance="worker-observed",
        available=True,
    )
    queries = json.loads(EXAMPLES.read_text(encoding="utf-8"))
    for name, spec in sorted(queries.items()):
        if name.startswith("_"):
            continue
        query = CapabilityQuery(
            require_all=frozenset(spec.get("require_all", [])),
            require_any=tuple(frozenset(group) for group in spec.get("require_any", [])),
            forbid=frozenset(spec.get("forbid", [])),
            prefer=frozenset(spec.get("prefer", [])),
            req_env=dict(spec["req_env"]) if "req_env" in spec else None,
            intent=spec.get("intent", "normal"),
        )
        fleet = resolve_fleet(query, [local], replicas=1)
        print(f"{name}: {fleet.verdict} selected={list(fleet.selected)}")
        for item in fleet.per_worker:
            if not item.eligible:
                print(f"  {item.worker_id}: {item.code} {list(item.missing)[:2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
