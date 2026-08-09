"""Deterministic capability-aware admission decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .errors import ValidationError
from .models import validate_job_plan
from .resources import evaluate_placement


@dataclass(frozen=True)
class WorkerSlot:
    worker_id: str
    capabilities: frozenset[str]
    active: int = 0
    concurrency_limit: int = 1
    available: bool = True
    resource_snapshot: dict[str, object] | None = None
    runtime_observation: dict[str, object] | None = None


@dataclass(frozen=True)
class ScheduleDecision:
    disposition: str
    worker_ids: tuple[str, ...]
    reason: str
    admissions: tuple[dict[str, object], ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {"disposition": self.disposition, "worker_ids": list(self.worker_ids), "reason": self.reason, "admissions": [dict(item) for item in self.admissions]}


def schedule(plan: object, workers: Iterable[WorkerSlot], *, replicas: int = 1, placement: object | None = None) -> ScheduleDecision:
    checked = validate_job_plan(plan)
    if not isinstance(replicas, int) or replicas < 1 or replicas > 64:
        raise ValidationError("replicas must be between 1 and 64")
    required = frozenset(checked["required_capabilities"])
    worker_list = list(workers)
    eligible = [worker for worker in worker_list if worker.available and worker.active < worker.concurrency_limit and required <= worker.capabilities]
    eligible.sort(key=lambda worker: worker.worker_id)
    admissions: list[dict[str, object]] = []
    if placement is not None:
        admitted: list[WorkerSlot] = []
        for worker in eligible:
            if worker.resource_snapshot is None:
                admission = {"worker_identity": worker.worker_id, "disposition": "UNKNOWN", "reason_code": "RESOURCE_OBSERVATION_UNKNOWN", "reason": "worker has no resource snapshot"}
            else:
                admission = evaluate_placement(placement, worker.resource_snapshot, worker.capabilities, worker.runtime_observation)
            admissions.append({"worker_id": worker.worker_id, **admission})
            if admission.get("disposition") == "PASS":
                admitted.append(worker)
        eligible = admitted
    if len(eligible) < replicas:
        missing = sorted(required - set().union(*(worker.capabilities for worker in worker_list)) if worker_list else required)
        if missing:
            reason = "CAPABILITY_UNAVAILABLE"
        elif placement is not None and admissions:
            reason = "RESOURCE_ADMISSION_UNAVAILABLE: " + "; ".join(f"{item['worker_id']}={item.get('reason_code', 'UNKNOWN')}" for item in admissions)
        else:
            reason = "ADMISSION_EXHAUSTED"
        return ScheduleDecision("UNKNOWN", (), f"{reason}: {missing}" if missing else reason, tuple(admissions))
    selected = tuple(worker.worker_id for worker in eligible[:replicas])
    return ScheduleDecision("PASS", selected, "exact capability and resource admission match" if placement is not None else "exact capability match and admission available", tuple(admissions))
