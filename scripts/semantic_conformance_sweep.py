#!/usr/bin/env python3
"""Distributed semantic-conformance sweep through MNCS Fabric machinery.

Builds one validated conformance job plan per (os, arch, backend) cell,
places each through the existing Fabric scheduler against the available
worker slots, executes placed cells through the existing executor path, and
aggregates per-cell outcomes into sweep evidence where unplaced or errored
cells are UNKNOWN obligations — never passes.

What this proves depends on what is actually online: cells placed on the
local worker execute for real through ``execute_local`` (labeled with the
local node identity); cells no worker can take (Windows, ARM, CUDA, RISC-V
emulation from a bare Linux x86_64 host, ...) are recorded as
CAPABILITY_UNAVAILABLE obligations. Temporary worker absence is UNKNOWN by
construction, not PASS.

Usage:
    scripts/semantic_conformance_sweep.py --program <contract.mncs>
        --library-dir <mncs-language/library> --output sweep-evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mncs_fabric import scheduler
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.errors import FabricError
from mncs_fabric.executor import execute_local
from mncs_fabric.node import collect_node_capabilities
from mncs_fabric.semantic_conformance import (
    SWEEP_PLAN_SCHEMA,
    aggregate_sweep,
    build_conformance_job_plan,
)

DEFAULT_CELLS = [
    {"os": "linux", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-research-bytecode"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-c11"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-llvm-ir"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-cranelift"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-ptx64"},
    {"os": "linux", "arch": "x86_64", "backend": "mncs-riscv32"},
    {"os": "windows", "arch": "x86_64", "backend": "mncs-portable-wasm-mvp"},
    {"os": "linux", "arch": "aarch64", "backend": "mncs-portable-wasm-mvp"},
]

LOCAL_OS = {"Linux": "linux", "Windows": "windows", "Darwin": "darwin"}.get(
    platform.system(), platform.system().lower()
)
LOCAL_ARCH = {"x86_64": "x86_64", "AMD64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
    platform.machine(), platform.machine()
)


def resolve_mncs(mncs_bin: str | None) -> str:
    if mncs_bin:
        path = Path(mncs_bin)
        if path.is_file():
            return str(path.resolve())
        raise SystemExit(f"mncs binary not found: {mncs_bin}")
    found = shutil.which("mncs")
    if found:
        return found
    raise SystemExit("no mncs binary on PATH (pass --mncs-bin)")


def local_slot(mncs_path: str) -> scheduler.WorkerSlot:
    capabilities = {f"os:{LOCAL_OS}", f"arch:{LOCAL_ARCH}", "tool:mncs"}
    return scheduler.WorkerSlot(worker_id="local-sweep-worker", capabilities=frozenset(capabilities))


def parse_report_summary(text: str) -> dict | None:
    try:
        start = text.index("{")
        document = json.loads(text[start:])
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or document.get("schema_version") != "mncs.conformance-report/1":
        return None
    return document.get("summary")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", required=True)
    parser.add_argument("--library-dir", default=None)
    parser.add_argument("--mncs-bin", default=None)
    parser.add_argument("--cells", default=None, help="JSON file with [{os, arch, backend}] (default matrix otherwise)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--cases", type=int, default=4)
    parser.add_argument("--step-budget", type=int, default=200000)
    parser.add_argument("--machine-label", default=None)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    mncs_path = resolve_mncs(args.mncs_bin)
    # The executor re-derives local capabilities from its own tool probe, so
    # the binary directory joins PATH: the probe then observes what is really
    # there instead of missing it. No capability is asserted, only made
    # observable.
    os.environ["PATH"] = str(Path(mncs_path).parent) + os.pathsep + os.environ.get("PATH", "")
    program_path = Path(args.program).resolve(strict=True)
    program_sha256 = hashlib.sha256(program_path.read_bytes()).hexdigest()
    cells = json.loads(Path(args.cells).read_text()) if args.cells else DEFAULT_CELLS
    machine_label = args.machine_label or socket.gethostname()

    with tempfile.TemporaryDirectory(prefix="mncs-sweep-bundle-") as bundle_dir, tempfile.TemporaryDirectory(
        prefix="mncs-sweep-results-"
    ) as results_dir:
        bundle_root = Path(bundle_dir)
        shutil.copyfile(program_path, bundle_root / program_path.name)
        with_library = False
        if args.library_dir:
            shutil.copytree(args.library_dir, bundle_root / "library", symlinks=False)
            with_library = True
        manifest = build_manifest(bundle_root)
        manifest_sha256 = manifest["manifest_identity"].split(":", 1)[1]

        slot = local_slot(mncs_path)
        node = collect_node_capabilities(machine_label)
        outcomes = []
        for index, cell in enumerate(cells):
            try:
                plan = build_conformance_job_plan(
                    job_id=f"sweep:{program_path.stem}:cell-{index:03d}",
                    program_sha256=program_sha256,
                    bundle_manifest_sha256=manifest_sha256,
                    mncs_argv0=mncs_path,
                    program_relpath=program_path.name,
                    backend=cell["backend"],
                    seed=args.seed,
                    cases=args.cases,
                    step_budget=args.step_budget,
                    os=cell["os"],
                    arch=cell["arch"],
                    with_library=with_library,
                )
            except FabricError as error:
                outcomes.append({"cell": cell, "disposition": "error", "detail": f"plan invalid: {error}"})
                continue
            decision = scheduler.schedule(plan, [slot], replicas=1)
            if decision.disposition != "PASS":
                outcomes.append({"cell": cell, "disposition": "unplaced", "detail": decision.reason})
                continue
            cell_results = Path(results_dir) / f"cell-{index:03d}"
            record = execute_local(plan, bundle_root, manifest, machine_label, results_dir=cell_results)
            report_file = cell_results / "conformance-report.json"
            if report_file.is_file():
                summary = json.loads(report_file.read_text()).get("summary", {})
            else:
                summary = parse_report_summary(record.get("stdout", {}).get("text", "") or "") or {}
            if record["outcome"] == "PASS":
                outcomes.append({
                    "cell": cell,
                    "disposition": "executed-pass",
                    "detail": f"executor PASS; report summary {summary}",
                })
            elif record["outcome"] == "FAIL" and summary.get("fail", 0) > 0:
                outcomes.append({
                    "cell": cell,
                    "disposition": "executed-fail",
                    "detail": f"contract failures observed; report summary {summary}",
                })
            elif record["termination_reason"] == "CAPABILITY_UNAVAILABLE":
                outcomes.append({"cell": cell, "disposition": "unplaced", "detail": record["termination_reason"]})
            else:
                outcomes.append({
                    "cell": cell,
                    "disposition": "error",
                    "detail": f"{record['outcome']}/{record['termination_reason']} (no contract observation)",
                })

        evidence = aggregate_sweep(outcomes)
        evidence["sweep_plan"] = {
            "schema_version": SWEEP_PLAN_SCHEMA,
            "program": str(program_path),
            "program_sha256": program_sha256,
            "mncs_argv0": mncs_path,
            "seed": args.seed,
            "cases": args.cases,
            "node": node,
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"verdict": evidence["verdict"], "counts": evidence["counts"]}))
        return 0


if __name__ == "__main__":
    sys.exit(main())
