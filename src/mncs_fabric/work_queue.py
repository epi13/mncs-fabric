"""Durable scheduled-work queue owned by the persistent Fabric controller.

Fabric admits and later dispatches work. Commons is not consulted. Recurrence
identity plus idempotency prevent duplicate recurring triggers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Mapping

from .availability import evaluate_availability, validate_availability_policy
from .canonical import attach_identity, sha256_identity
from .errors import ValidationError
from .node import utc_now
from .store import FabricLedger, iter_ledger_records

SCHEDULED_WORK_SCHEMA = "mncs-fabric.scheduled-work.v0.1"
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


class WorkQueue:
    def __init__(self, ledger: FabricLedger) -> None:
        self.ledger = ledger
        self._state_cache: tuple[dict[str, dict[str, Any]], bool] | None = None
        self._state_token: tuple[int, int] | None = None

    def _ensure_state(self) -> tuple[dict[str, dict[str, Any]], bool]:
        if not self.ledger.path.exists():
            self._state_cache = ({}, False)
            self._state_token = None
            return self._state_cache
        stat = self.ledger.path.stat()
        token = (stat.st_size, stat.st_mtime_ns)
        if token != self._state_token:
            latest: dict[str, dict[str, Any]] = {}
            paused = False
            for entry in iter_ledger_records(self.ledger):
                rtype = entry.get("record_type")
                rec = entry.get("record", {})
                if rtype == "scheduled.work":
                    wid = rec.get("work_id")
                    if wid:
                        state = rec.get("state")
                        if state in _TERMINAL:
                            latest.pop(str(wid), None)
                        else:
                            latest[str(wid)] = dict(rec)
                elif rtype == "scheduled.control":
                    st = rec.get("state")
                    if st == "PAUSED":
                        paused = True
                    elif st == "RESUMED":
                        paused = False
            self._state_cache = (latest, paused)
            self._state_token = token
        assert self._state_cache is not None
        return self._state_cache

    def records(self, work_id: str | None = None) -> list[dict[str, Any]]:
        # Queue state is derived from complete work histories; a bounded read
        # would silently drop older queued work and pause/resume transitions.
        values = [dict(entry["record"]) for entry in self.ledger.all_records(record_type="scheduled.work")]
        if work_id is not None:
            values = [item for item in values if item.get("work_id") == work_id]
        return values

    def latest(self, work_id: str) -> dict[str, Any]:
        latest_map, _ = self._ensure_state()
        current = latest_map.get(work_id)
        if current is not None:
            return dict(current)
        # Terminal work is intentionally not retained in the live projection;
        # resolve it from the canonical history only when explicitly asked.
        latest: dict[str, Any] | None = None
        for entry in iter_ledger_records(self.ledger, record_type="scheduled.work"):
            record = entry.get("record", {})
            if record.get("work_id") == work_id:
                latest = dict(record)
        if latest is None:
            raise ValidationError("scheduled work identity is unknown")
        return latest

    def enqueue(self, value: Mapping[str, Any], *, client_identity: str) -> dict[str, Any]:
        if not isinstance(client_identity, str) or not client_identity:
            raise ValidationError("scheduled work client identity is invalid")
        idempotency_key = value.get("idempotency_key") or value.get("recurrence_identity")
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
            raise ValidationError("scheduled work idempotency key is invalid")
        required_capabilities = value.get("required_capabilities") or []
        if not isinstance(required_capabilities, list) or any(
            not isinstance(item, str) or not item for item in required_capabilities
        ):
            raise ValidationError("scheduled work required_capabilities are invalid")
        recurrence = value.get("recurrence_identity")
        if recurrence is not None and (not isinstance(recurrence, str) or not recurrence):
            raise ValidationError("scheduled work recurrence identity is invalid")
        work_id = sha256_identity({"client_identity": client_identity, "idempotency_key": idempotency_key})
        submitted = {
            "schema_version": SCHEDULED_WORK_SCHEMA,
            "work_id": work_id,
            "state": "QUEUED",
            "client_identity": client_identity,
            "idempotency_key": idempotency_key,
            "recurrence_identity": recurrence,
            "workload_class": str(value.get("workload_class") or "python"),
            "required_capabilities": [str(item) for item in required_capabilities],
            "required_worker_id": value.get("required_worker_id"),
            "priority": int(value.get("priority") or 100),
            "project": value.get("project"),
            "observed_at": utc_now(),
            "attempt": 1,
            "authority": "persistent-fabric",
            "commons_authority": "none",
        }
        if submitted["required_worker_id"] is not None and not isinstance(submitted["required_worker_id"], str):
            raise ValidationError("scheduled work required_worker_id is invalid")

        def accept(records: list[dict[str, Any]]) -> None:
            prior = [entry["record"] for entry in records if entry["record"].get("work_id") == work_id]
            if not prior:
                return
            raise _DuplicateScheduledWork

        try:
            self.ledger.append_if("scheduled.work", attach_identity(submitted, "event_identity"), accept)
        except _DuplicateScheduledWork:
            return self.latest(work_id)
        latest_map, paused = self._ensure_state()
        latest_map[work_id] = submitted
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._state_token = (stat.st_size, stat.st_mtime_ns)
        return submitted

    def pause(self) -> dict[str, Any]:
        event = {
            "schema_version": SCHEDULED_WORK_SCHEMA,
            "work_id": "operator-pause",
            "state": "PAUSED",
            "observed_at": utc_now(),
        }
        self.ledger.append("scheduled.control", attach_identity(event, "event_identity"))
        latest_map, _ = self._ensure_state()
        self._state_cache = (latest_map, True)
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._state_token = (stat.st_size, stat.st_mtime_ns)
        return {"paused": True}

    def resume(self) -> dict[str, Any]:
        event = {
            "schema_version": SCHEDULED_WORK_SCHEMA,
            "work_id": "operator-pause",
            "state": "RESUMED",
            "observed_at": utc_now(),
        }
        self.ledger.append("scheduled.control", attach_identity(event, "event_identity"))
        latest_map, _ = self._ensure_state()
        self._state_cache = (latest_map, False)
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._state_token = (stat.st_size, stat.st_mtime_ns)
        return {"paused": False}

    def paused(self) -> bool:
        _, paused = self._ensure_state()
        return paused

    def queued(self) -> list[dict[str, Any]]:
        latest_map, _ = self._ensure_state()
        return [
            dict(item)
            for item in latest_map.values()
            if item.get("state") == "QUEUED" and item.get("work_id") != "operator-pause"
        ]

    def _append_state(self, work_id: str, state: str, **fields: Any) -> dict[str, Any]:
        latest = self.latest(work_id)
        event = {
            "schema_version": SCHEDULED_WORK_SCHEMA,
            "work_id": work_id,
            "state": state,
            "attempt": latest.get("attempt", 1),
            "observed_at": utc_now(),
            **fields,
        }
        self.ledger.append("scheduled.work", attach_identity(event, "event_identity"))
        latest_map, paused = self._ensure_state()
        if state in _TERMINAL:
            latest_map.pop(work_id, None)
        else:
            latest_map[work_id] = event
        if self.ledger.path.exists():
            stat = self.ledger.path.stat()
            self._state_token = (stat.st_size, stat.st_mtime_ns)
        return event

    def tick(
        self,
        *,
        policy: Mapping[str, Any],
        workers: list[Mapping[str, Any]],
        now: datetime | None = None,
        dispatcher: Callable[[dict[str, Any], str], Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        validate_availability_policy(policy)
        if self.paused():
            return {"paused": True, "dispatched": [], "held": [item["work_id"] for item in self.queued()]}
        dispatched: list[dict[str, Any]] = []
        held: list[dict[str, Any]] = []
        for work in sorted(self.queued(), key=lambda item: (int(item.get("priority") or 100), item["work_id"])):
            selected = _select_worker(work, workers, policy, now=now)
            if selected is None:
                held.append({"work_id": work["work_id"], "reason": "NO_ELIGIBLE_WORKER"})
                continue
            if dispatcher is not None:
                result = dict(dispatcher(work, selected))
                state = str(result.get("state") or "DISPATCHED")
                self._append_state(work["work_id"], state, worker_id=selected, result=result)
            else:
                self._append_state(work["work_id"], "DISPATCHED", worker_id=selected)
            dispatched.append({"work_id": work["work_id"], "worker_id": selected})
        return {"paused": False, "dispatched": dispatched, "held": held}


def _select_worker(
    work: Mapping[str, Any],
    workers: list[Mapping[str, Any]],
    policy: Mapping[str, Any],
    *,
    now: datetime | None,
) -> str | None:
    required = set(work.get("required_capabilities") or [])
    pinned = work.get("required_worker_id")
    for worker in workers:
        worker_id = str(worker.get("worker_id") or "")
        if not worker_id:
            continue
        if pinned and worker_id != pinned:
            continue
        if worker.get("availability") != "AVAILABLE":
            continue
        capabilities = set(worker.get("capabilities") or [])
        if required and not required <= capabilities:
            continue
        window = evaluate_availability(
            policy,
            worker_id,
            now=now,
            workload_class=str(work.get("workload_class") or "python"),
        )
        if window["eligible"]:
            return worker_id
    return None


class _DuplicateScheduledWork(Exception):
    """Idempotent enqueue of an already accepted scheduled work item."""
