"""Deterministic capability-aware admission decisions.

Scheduling is pre-execution capability resolution, never trial execution.
A workload's requirements are checked against each worker's observed
capabilities, classified environment, declared policy, liveness, and
observation freshness *before* any dispatch. When no worker qualifies,
the result is ``NO_ELIGIBLE_WORKER`` with per-worker machine-readable
reasons — a first-class scheduling outcome, not a generic failure.

Worker names never participate in decisions. Selection among eligible
workers uses only capability match and preference rank.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .capability_resolution import (
    CapabilityQuery,
    FleetResolution,
    WorkerResolution,
    WorkerSnapshot,
    explain_selection,
    resolve_fleet,
)
from .errors import ValidationError
from .management import management_allows_work
from .models import validate_job_plan


@dataclass(frozen=True)
class WorkerSlot:
    worker_id: str
    capabilities: frozenset[str]
    active: int = 0
    concurrency_limit: int = 1
    available: bool = True
    resource_snapshot: dict[str, object] | None = None
    runtime_observation: dict[str, object] | None = None
    runtime_capability_observation: dict[str, object] | None = None
    management_state: str | None = None
    # Capability-resolution inputs (all default to the historic behavior so
    # live-derived slots keep scheduling while observation-backed slots
    # carry their age, provenance, environment, and declared policy).
    liveness: str = "AVAILABLE"
    capability_age_seconds: float | None = None
    provenance: str = "worker-observed"
    worker_env: dict[str, object] | None = None
    worker_policy: dict[str, object] | None = None


@dataclass(frozen=True)
class ScheduleDecision:
    disposition: str
    worker_ids: tuple[str, ...]
    reason: str
    admissions: tuple[dict[str, object], ...] = ()
    resolution: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "disposition": self.disposition,
            "worker_ids": list(self.worker_ids),
            "reason": self.reason,
            "admissions": [dict(item) for item in self.admissions],
        }
        if self.resolution is not None:
            value["resolution"] = dict(self.resolution)
        return value


def _snapshot_for_slot(worker: WorkerSlot) -> WorkerSnapshot:
    return WorkerSnapshot(
        worker_id=worker.worker_id,
        capabilities=frozenset(worker.capabilities),
        env=dict(worker.worker_env) if isinstance(worker.worker_env, dict) else None,
        policy=dict(worker.worker_policy) if isinstance(worker.worker_policy, dict) else None,
        liveness=worker.liveness,
        capability_age_seconds=worker.capability_age_seconds,
        provenance=worker.provenance,
        available=bool(worker.available),
        active=int(worker.active),
        concurrency_limit=int(worker.concurrency_limit),
        management_state=worker.management_state,
    )


def explain_eligibility(
    required: Iterable[str],
    workers: Iterable[WorkerSlot],
    *,
    intent: str = "normal",
    prefer: Iterable[str] = (),
) -> FleetResolution:
    """Machine-readable eligibility for a capability set over workers."""
    query = CapabilityQuery(
        require_all=frozenset(required),
        prefer=frozenset(prefer),
        intent=intent,
    )
    snapshots = [_snapshot_for_slot(worker) for worker in workers]
    return resolve_fleet(query, snapshots, replicas=1)


def schedule(
    plan: object,
    workers: Iterable[WorkerSlot],
    *,
    replicas: int = 1,
    placement: object | None = None,
    intent: str = "normal",
    prefer: Iterable[str] = (),
    query: CapabilityQuery | None = None,
) -> ScheduleDecision:
    checked = validate_job_plan(plan)
    if not isinstance(replicas, int) or replicas < 1 or replicas > 64:
        raise ValidationError("replicas must be between 1 and 64")
    required = frozenset(checked["required_capabilities"])
    prefer_set = frozenset(prefer)
    worker_list = list(workers)
    if query is None:
        query = CapabilityQuery(require_all=required, prefer=prefer_set, intent=intent)
    else:
        if not isinstance(query, CapabilityQuery):
            raise ValidationError("query must be a CapabilityQuery")
        query = CapabilityQuery(
            require_all=frozenset(query.require_all) | required,
            require_any=tuple(query.require_any),
            forbid=frozenset(query.forbid),
            prefer=frozenset(query.prefer) | prefer_set,
            req_env=dict(query.req_env) if query.req_env is not None else None,
            intent=query.intent,
        )
    snapshots = [_snapshot_for_slot(worker) for worker in worker_list]
    fleet = resolve_fleet(query, snapshots, replicas=1)
    by_id = {item.worker_id: item for item in fleet.per_worker}
    eligible = [
        worker
        for worker in worker_list
        if (by_id.get(worker.worker_id) is not None and by_id[worker.worker_id].eligible)
        and worker.active < worker.concurrency_limit
        and management_allows_work(worker.management_state)
    ]
    eligible.sort(
        key=lambda worker: (
            -len(by_id[worker.worker_id].preferred_hits),
            worker.worker_id,
        )
    )
    resolution = explain_selection(fleet)
    admissions: list[dict[str, object]] = []
    if placement is not None:
        from .resources import evaluate_placement

        admitted: list[WorkerSlot] = []
        for worker in eligible:
            if worker.resource_snapshot is None:
                admission = {"worker_identity": worker.worker_id, "disposition": "UNKNOWN", "reason_code": "RESOURCE_OBSERVATION_UNKNOWN", "reason": "worker has no resource snapshot"}
            else:
                admission = evaluate_placement(placement, worker.resource_snapshot, worker.capabilities, worker.runtime_observation, worker.runtime_capability_observation)
            admissions.append({"worker_id": worker.worker_id, **admission})
            if admission.get("disposition") == "PASS":
                admitted.append(worker)
        eligible = admitted
    if len(eligible) < replicas:
        missing = sorted(required - set().union(*(worker.capabilities for worker in worker_list)) if worker_list else required)
        per_worker = "; ".join(
            f"{item.worker_id}={item.code}" + (f"({item.detail})" if item.detail else "")
            for item in sorted(fleet.per_worker, key=lambda item: item.worker_id)
        )
        if fleet.verdict == "NO_ELIGIBLE_WORKER":
            reason = "NO_ELIGIBLE_WORKER"
            if missing:
                reason += f": CAPABILITY_UNAVAILABLE {missing}"
            else:
                codes = sorted({item.code for item in fleet.per_worker})
                reason += f": {', '.join(codes)}"
        elif missing:
            reason = f"CAPABILITY_UNAVAILABLE {missing}"
        elif placement is not None and admissions:
            reason = "RESOURCE_ADMISSION_UNAVAILABLE: " + "; ".join(f"{item['worker_id']}={item.get('reason_code', 'UNKNOWN')}" for item in admissions)
        else:
            reason = "ADMISSION_EXHAUSTED"
        if per_worker:
            reason = f"{reason} | eligibility: {per_worker}"
        return ScheduleDecision("UNKNOWN", (), reason, tuple(admissions), resolution)
    selected = tuple(worker.worker_id for worker in eligible[:replicas])
    return ScheduleDecision("PASS", selected, "exact capability and resource admission match" if placement is not None else "exact capability match and admission available", tuple(admissions), resolution)
