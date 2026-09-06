"""Capability-scheduled semantic conformance for MNCS Fabric.

A semantic conformance sweep validates one MNCS contract program across a
matrix of (os, arch, backend) cells. Each cell becomes a standard Fabric job
plan (``mncs-fabric.job-plan.v0.1``) whose ``argv`` runs the observable
``mncs conformance`` entrypoint; placement uses only the existing scheduler
over worker capability sets (``os:*``, ``arch:*``, ``tool:mncs``) — worker
names never appear in scheduling logic or evidence.

Verdict discipline (mirrors the mncs-actions conformance gate):
- any executed FAIL -> FAIL;
- executed clean but a cell could not be placed or errored -> UNKNOWN is
  recorded per cell, and the sweep verdict is PASS with capability
  obligations only when every *executed* cell passed. Unplaced cells are
  obligations (CAPABILITY_UNAVAILABLE), never passes and never silent.
- a sweep that executed nothing is UNKNOWN (nothing was proven).

No new network behavior lives here: this module builds validated plans and
aggregates evidence. Dispatch rides the existing executor/service paths.
"""

from __future__ import annotations

from typing import Any, Mapping

from .errors import ValidationError
from .models import validate_job_plan

SWEEP_PLAN_SCHEMA = "mncs-fabric.semantic-conformance-sweep/0.1"
SWEEP_EVIDENCE_SCHEMA = "mncs-fabric.semantic-conformance-evidence/0.1"

# Backends the conformance runner can execute in-process on any worker with
# an mncs binary. Accelerator/emulator backends (PTX/CUDA, RISC-V, eBPF)
# lower to artifacts but report UNSUPPORTED without local drivers; they stay
# schedulable by os/arch/tool so the UNSUPPORTED observation itself is the
# evidence, and no capability is overclaimed to filter them out.
PORTABLE_BACKENDS = (
    "mncs-portable-wasm-mvp",
    "mncs-research-bytecode",
    "mncs-c11",
    "mncs-llvm-ir",
    "mncs-cranelift",
)

ACCELERATOR_BACKENDS = ("mncs-ptx64",)
EMULATED_BACKENDS = ("mncs-riscv32", "mncs-ebpf")

KNOWN_BACKENDS = PORTABLE_BACKENDS + ACCELERATOR_BACKENDS + EMULATED_BACKENDS


def conformance_capabilities(*, os: str, arch: str) -> list[str]:
    """Required capabilities for one conformance cell.

    Only verified inventory tokens: ``os:*`` and ``arch:*`` come from every
    worker record, and ``tool:mncs`` is advertised by workers whose tool
    probe observes an mncs binary. Scheduling never names machines.
    """
    for field, value in (("os", os), ("arch", arch)):
        if not isinstance(value, str) or not value or len(value) > 64:
            raise ValidationError(f"conformance cell {field} must be a non-empty bounded string")
        if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for char in value):
            raise ValidationError(f"conformance cell {field} has unsupported characters")
    return [f"os:{os}", f"arch:{arch}", "tool:mncs"]


def build_conformance_job_plan(
    *,
    job_id: str,
    program_sha256: str,
    bundle_manifest_sha256: str,
    mncs_argv0: str,
    program_relpath: str,
    backend: str,
    seed: int,
    cases: int,
    step_budget: int,
    os: str,
    arch: str,
    timeout_seconds: float = 600.0,
    with_library: bool = False,
) -> dict[str, Any]:
    """Build one validated conformance job plan for a single matrix cell."""
    if backend not in KNOWN_BACKENDS:
        raise ValidationError(f"unknown conformance backend {backend!r}")
    for label, value in (("program_sha256", program_sha256), ("bundle_manifest_sha256", bundle_manifest_sha256)):
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValidationError(f"{label} must be a lowercase sha256 hex digest")
    if not isinstance(mncs_argv0, str) or not mncs_argv0.startswith("/"):
        raise ValidationError("mncs_argv0 must be an absolute executable path")
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise ValidationError("seed must be a non-negative integer")
    if not isinstance(cases, int) or isinstance(cases, bool) or not 1 <= cases <= 512:
        raise ValidationError("cases must be between 1 and 512")
    if not isinstance(step_budget, int) or isinstance(step_budget, bool) or step_budget <= 0:
        raise ValidationError("step_budget must be positive")
    from .models import safe_relative_path

    program_relpath = safe_relative_path(program_relpath, "program_relpath")
    environment: dict[str, str] = {}
    if with_library:
        environment["MNCS_LIBRARY_PATH"] = "library"
    plan = {
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": job_id,
        "candidate_identity": "sha256:" + program_sha256,
        "evaluator_identity": None,
        "artifact_manifest_identity": "sha256:" + bundle_manifest_sha256,
        "argv": [
            mncs_argv0,
            "conformance",
            program_relpath,
            "--cases",
            str(cases),
            "--seed",
            str(seed),
            "--backends",
            backend,
            "--step-budget",
            str(step_budget),
            "--output",
            "conformance-report.json",
        ],
        "working_directory": ".",
        "timeout_seconds": timeout_seconds,
        "output_limit_bytes": 4 * 1024 * 1024,
        "environment": environment,
        "required_capabilities": conformance_capabilities(os=os, arch=arch),
        "result_paths": ["conformance-report.json"],
        "network_policy": "DECLARED_OFFLINE",
    }
    return validate_job_plan(plan)


def plan_sweep(
    cells: list[Mapping[str, Any]],
    *,
    job_id_prefix: str,
    program_sha256: str,
    bundle_manifest_sha256: str,
    mncs_argv0: str,
    program_relpath: str,
    seed: int,
    cases: int,
    step_budget: int,
    with_library: bool = False,
) -> list[dict[str, Any]]:
    """Build one validated job plan per matrix cell.

    Each cell is ``{"os": ..., "arch": ..., "backend": ...}``. Cells carry
    capabilities only; worker selection happens in the scheduler.
    """
    plans = []
    for index, cell in enumerate(cells):
        if not isinstance(cell, Mapping):
            raise ValidationError("sweep cell must be an object")
        plans.append(
            build_conformance_job_plan(
                job_id=f"{job_id_prefix}:cell-{index:03d}",
                program_sha256=program_sha256,
                bundle_manifest_sha256=bundle_manifest_sha256,
                mncs_argv0=mncs_argv0,
                program_relpath=program_relpath,
                backend=cell["backend"],
                seed=seed,
                cases=cases,
                step_budget=step_budget,
                os=cell["os"],
                arch=cell["arch"],
                with_library=with_library,
            )
        )
    return plans


def aggregate_sweep(
    outcomes: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate per-cell outcomes into sweep evidence.

    Each outcome is ``{"cell": {...}, "disposition": ..., "detail": ...}``
    where disposition is one of ``executed-pass``, ``executed-fail``,
    ``unplaced`` (scheduler CAPABILITY_UNAVAILABLE), or ``error`` (executor
    UNKNOWN). Unplaced and errored cells are obligations, never passes.
    """
    cells: list[dict[str, Any]] = []
    counts = {"executed-pass": 0, "executed-fail": 0, "unplaced": 0, "error": 0}
    obligations: list[str] = []
    for outcome in outcomes:
        if not isinstance(outcome, Mapping):
            raise ValidationError("sweep outcome must be an object")
        cell = outcome.get("cell")
        disposition = outcome.get("disposition")
        detail = outcome.get("detail", "")
        if disposition not in counts:
            raise ValidationError(f"unknown sweep disposition {disposition!r}")
        counts[disposition] += 1
        if disposition in ("unplaced", "error"):
            obligations.append(f"{cell}: {disposition} ({detail})")
        cells.append({"cell": dict(cell) if isinstance(cell, Mapping) else cell, "disposition": disposition, "detail": detail})
    if counts["executed-fail"] > 0:
        verdict = "FAIL"
    elif counts["executed-pass"] == 0:
        verdict = "UNKNOWN"
    else:
        verdict = "PASS"
    return {
        "schema_version": SWEEP_EVIDENCE_SCHEMA,
        "verdict": verdict,
        "counts": dict(counts),
        "cells": cells,
        "obligations": sorted(obligations),
    }
