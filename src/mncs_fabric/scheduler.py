"""Deterministic capability-aware admission decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .errors import ValidationError
from .models import validate_job_plan


@dataclass(frozen=True)
class WorkerSlot:
    worker_id: str
    capabilities: frozenset[str]
    active: int = 0
    concurrency_limit: int = 1
    available: bool = True


@dataclass(frozen=True)
class ScheduleDecision:
    disposition: str
    worker_ids: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"disposition": self.disposition, "worker_ids": list(self.worker_ids), "reason": self.reason}


def schedule(plan: object, workers: Iterable[WorkerSlot], *, replicas: int = 1) -> ScheduleDecision:
    checked = validate_job_plan(plan)
    if not isinstance(replicas, int) or replicas < 1 or replicas > 64:
        raise ValidationError("replicas must be between 1 and 64")
    required = frozenset(checked["required_capabilities"])
    worker_list = list(workers)
    eligible = [worker for worker in worker_list if worker.available and worker.active < worker.concurrency_limit and required <= worker.capabilities]
    eligible.sort(key=lambda worker: worker.worker_id)
    if len(eligible) < replicas:
        missing = sorted(required - set().union(*(worker.capabilities for worker in worker_list)) if worker_list else required)
        reason = "CAPABILITY_UNAVAILABLE" if missing else "ADMISSION_EXHAUSTED"
        return ScheduleDecision("UNKNOWN", (), f"{reason}: {missing}" if missing else reason)
    selected = tuple(worker.worker_id for worker in eligible[:replicas])
    return ScheduleDecision("PASS", selected, "exact capability match and admission available")
