#!/usr/bin/env python3
"""Collect real-fleet capability evidence for the capability-aware campaign.

Refreshes every registered worker, classifies what is observable, runs
the campaign's cross-platform queries (linux-only, windows-native, cuda,
ebpf, musl-preference, privileged intent, stable protection), and writes
a sanitized evidence document. Workers that are offline or unregistered
(worker-03/04 pre-conversion, Raspberry Pi) are recorded truthfully as
such — never fabricated.

Usage:
    python3 scripts/collect_fleet_capability_evidence.py --registry PATH \
        --controller-id ID --output development-evidence/FILE.json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mncs_fabric.api import FabricClient  # noqa: E402
from mncs_fabric.capability_resolution import (  # noqa: E402
    CapabilityQuery,
    WorkerSnapshot,
    default_policy,
    resolve_fleet,
)
from mncs_fabric.node import capability_names, collect_node_capabilities  # noqa: E402
from mncs_fabric.platform_probe import env_from_node  # noqa: E402

QUERIES = {
    "linux-only": CapabilityQuery(require_all=frozenset({"os:linux"})),
    "windows-native": CapabilityQuery(require_all=frozenset({"os:windows"})),
    "x86_64": CapabilityQuery(require_all=frozenset({"arch:x86_64"})),
    "cuda-presence": CapabilityQuery(require_all=frozenset({"accelerator:cuda"})),
    "ebpf": CapabilityQuery(require_all=frozenset({"kernel:ebpf"})),
    "cuda-floor-6-0": CapabilityQuery(
        require_all=frozenset({"os:linux"}),
        req_env={"require_cuda": True, "cuda_major": 6, "cuda_minor": 0},
    ),
    "musl-prefer": CapabilityQuery(
        require_all=frozenset({"os:linux"}),
        prefer=frozenset({"libc:musl"}),
    ),
    "privileged-stable-default": CapabilityQuery(
        require_all=frozenset({"os:linux"}), intent="privileged"
    ),
    "normal-work": CapabilityQuery(require_all=frozenset({"os:linux"}), intent="normal"),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        client = FabricClient(args.controller_id, Path(directory) / "ctl.jsonl")
        client.load_registry(Path(args.registry))
        states = client.refresh_workers()

    snapshots: list[WorkerSnapshot] = []
    workers: list[dict] = []
    for state in states:
        description = state.get("description") or {}
        node = description.get("node") or {}
        captured = description.get("captured_at")
        snapshots.append(
            WorkerSnapshot(
                worker_id=state.get("worker_id", "unknown"),
                capabilities=frozenset(capability_names(node)) if node else frozenset(),
                env=env_from_node(node) if node else None,
                policy=default_policy(),
                liveness="AVAILABLE" if state.get("availability") == "AVAILABLE" else "UNAVAILABLE",
                capability_age_seconds=0.0 if captured else None,
                provenance="worker-observed",
                available=state.get("availability") == "AVAILABLE",
            )
        )
        workers.append({
            "worker_id": state.get("worker_id"),
            "availability": state.get("availability"),
            "transport": state.get("transport"),
            "liveness_fresh": state.get("liveness_fresh"),
            "os": node.get("os"),
            "arch": node.get("architecture"),
            "tools": sorted((node.get("tools") or {}).keys()),
            "has_platform_section": isinstance(node.get("platform"), dict),
            "tokens": sorted(capability_names(node)) if node else [],
        })

    controller_node = collect_node_capabilities("controller")
    snapshots.append(
        WorkerSnapshot(
            worker_id="controller",
            capabilities=frozenset(capability_names(controller_node)),
            env=env_from_node(controller_node),
            policy=default_policy(),
            liveness="AVAILABLE",
            capability_age_seconds=None,
            provenance="worker-observed",
            available=True,
        )
    )
    workers.append({
        "worker_id": "controller",
        "availability": "LOCAL",
        "os": controller_node.get("os"),
        "arch": controller_node.get("architecture"),
        "tools": sorted(controller_node.get("tools", {}).keys()),
        "has_platform_section": True,
        "tokens": sorted(capability_names(controller_node)),
    })

    results = {}
    for name, query in QUERIES.items():
        fleet = resolve_fleet(query, snapshots, replicas=1)
        results[name] = fleet.as_dict()

    document = {
        "schema_version": "mncs-fabric.capability-fleet-evidence.v0.1",
        "claim_boundary": (
            "worker-observed capability snapshot plus deterministic query "
            "outcomes; not attestation, continuous availability, or conformance"
        ),
        "unregistered_workers": {
            "worker-03": "unregistered: pre-conversion experimental target (NixOS planned); no capabilities claimed",
            "worker-04": "unregistered: pre-conversion experimental target (Alpine/musl planned); no capabilities claimed",
            "raspberry-pi": "unregistered at collection time; no capabilities claimed",
        },
        "workers": workers,
        "queries": results,
    }
    Path(args.output).write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
    for name, result in results.items():
        print(f"{name}: {result['verdict']} selected={result['selected']}")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
