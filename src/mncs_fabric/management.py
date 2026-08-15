"""Controller-owned worker management state distinct from liveness.

Liveness remains an authenticated contact observation.  Management state is
the operator/controller lifecycle used to keep maintenance and the scheduler
from colliding.  A worker that fails certification does not become READY.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ProtocolError, ValidationError
from .node import utc_now
from .store import FabricLedger

MANAGEMENT_STATE_SCHEMA = "mncs-fabric.management-state.v0.1"
MANAGEMENT_STATES = frozenset({
    "READY",
    "BUSY",
    "DRAINING",
    "MAINTENANCE",
    "VERIFYING",
    "DEGRADED",
    "QUARANTINED",
})
SCHEDULABLE_STATES = frozenset({"READY", "BUSY"})
CERTIFICATION_STATUSES = frozenset({"CERTIFIED", "FAILED", "UNKNOWN", "NOT_RUN"})
_TRANSITIONS = {
    "READY": frozenset({"BUSY", "DRAINING", "MAINTENANCE", "QUARANTINED", "DEGRADED"}),
    "BUSY": frozenset({"READY", "DRAINING", "QUARANTINED"}),
    "DRAINING": frozenset({"MAINTENANCE", "READY", "QUARANTINED", "DEGRADED"}),
    "MAINTENANCE": frozenset({"VERIFYING", "DEGRADED", "QUARANTINED", "READY"}),
    "VERIFYING": frozenset({"READY", "DEGRADED", "QUARANTINED", "MAINTENANCE"}),
    "DEGRADED": frozenset({"DRAINING", "MAINTENANCE", "QUARANTINED", "READY"}),
    "QUARANTINED": frozenset({"DRAINING", "MAINTENANCE", "VERIFYING", "READY"}),
}


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _optional_identity(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValidationError(f"{field} must be a sha256 identity or null")
    return value


def build_management_state(
    *,
    worker_id: str,
    state: str,
    reason: str,
    active_jobs: int = 0,
    certification_status: str = "NOT_RUN",
    last_inventory_identity: str | None = None,
    last_plan_identity: str | None = None,
    last_receipt_identity: str | None = None,
    last_certification_identity: str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    if state not in MANAGEMENT_STATES:
        raise ValidationError("management state is unsupported")
    if certification_status not in CERTIFICATION_STATUSES:
        raise ValidationError("certification status is unsupported")
    if not isinstance(active_jobs, int) or isinstance(active_jobs, bool) or active_jobs < 0 or active_jobs > 1024:
        raise ValidationError("active_jobs is invalid")
    if state == "READY" and certification_status == "FAILED":
        raise ValidationError("a worker that failed certification cannot be READY")
    value = {
        "schema_version": MANAGEMENT_STATE_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "state": state,
        "reason": _text(reason, "reason", 512),
        "updated_at": updated_at or utc_now(),
        "active_jobs": active_jobs,
        "certification_status": certification_status,
        "last_inventory_identity": last_inventory_identity,
        "last_plan_identity": last_plan_identity,
        "last_receipt_identity": last_receipt_identity,
        "last_certification_identity": last_certification_identity,
        "claim_boundary": "controller-owned management lifecycle; not liveness, honesty, or attestation",
    }
    return attach_identity(value, "management_state_identity")


def validate_management_state(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != MANAGEMENT_STATE_SCHEMA:
        raise ValidationError("unsupported management-state schema")
    required = {
        "schema_version", "worker_identity", "state", "reason", "updated_at",
        "active_jobs", "certification_status", "last_inventory_identity",
        "last_plan_identity", "last_receipt_identity", "last_certification_identity",
        "claim_boundary", "management_state_identity",
    }
    if set(value) != required or not verify_identity(value, "management_state_identity"):
        raise ValidationError("management-state fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("management state is bound to another worker")
    if value["state"] not in MANAGEMENT_STATES:
        raise ValidationError("management state is unsupported")
    if value["certification_status"] not in CERTIFICATION_STATUSES:
        raise ValidationError("certification status is unsupported")
    if value["state"] == "READY" and value["certification_status"] == "FAILED":
        raise ValidationError("a worker that failed certification cannot be READY")
    _optional_identity(value["last_inventory_identity"], "last_inventory_identity")
    _optional_identity(value["last_plan_identity"], "last_plan_identity")
    _optional_identity(value["last_receipt_identity"], "last_receipt_identity")
    _optional_identity(value["last_certification_identity"], "last_certification_identity")
    return dict(value)


def management_allows_work(state: str | None) -> bool:
    return state in {None, *SCHEDULABLE_STATES}


def can_transition(current: str, target: str) -> bool:
    if current == target:
        return True
    return target in _TRANSITIONS.get(current, frozenset())


def transition_management_state(current: Mapping[str, Any], *, state: str, reason: str, **updates: Any) -> dict[str, Any]:
    checked = validate_management_state(current)
    if not can_transition(checked["state"], state):
        raise ProtocolError(f"management transition {checked['state']} -> {state} is not allowed")
    payload = {
        "worker_id": checked["worker_identity"],
        "state": state,
        "reason": reason,
        "active_jobs": updates.get("active_jobs", checked["active_jobs"]),
        "certification_status": updates.get("certification_status", checked["certification_status"]),
        "last_inventory_identity": updates.get("last_inventory_identity", checked["last_inventory_identity"]),
        "last_plan_identity": updates.get("last_plan_identity", checked["last_plan_identity"]),
        "last_receipt_identity": updates.get("last_receipt_identity", checked["last_receipt_identity"]),
        "last_certification_identity": updates.get("last_certification_identity", checked["last_certification_identity"]),
        "updated_at": updates.get("updated_at"),
    }
    return build_management_state(**payload)


class ManagementStore:
    """Append-only controller ledger for management state and desired-state assignments."""

    def __init__(self, path: Path) -> None:
        self.ledger = FabricLedger(Path(path))

    def state(self, worker_id: str) -> dict[str, Any] | None:
        latest = None
        for entry in self.ledger.all_records():
            if entry["record_type"] != "management.state":
                continue
            record = entry["record"]
            if record.get("worker_identity") == worker_id:
                latest = record
        return validate_management_state(latest, expected_worker_id=worker_id) if latest else None

    def ensure(self, worker_id: str, *, reason: str = "initialized") -> dict[str, Any]:
        current = self.state(worker_id)
        if current is not None:
            return current
        created = build_management_state(worker_id=worker_id, state="READY", reason=reason, certification_status="UNKNOWN")
        self.ledger.append("management.state", created)
        return created

    def assign_desired_state(self, desired: Mapping[str, Any]) -> dict[str, Any]:
        from .desired_state import validate_desired_state

        checked = validate_desired_state(desired)
        self.ledger.append("management.desired-state", dict(checked))
        return dict(checked)

    def desired_state(self, worker_id: str) -> dict[str, Any] | None:
        latest = None
        for entry in self.ledger.all_records():
            if entry["record_type"] != "management.desired-state":
                continue
            record = entry["record"]
            if record.get("worker_identity") == worker_id:
                latest = record
        return dict(latest) if latest is not None else None

    def set_state(self, worker_id: str, *, state: str, reason: str, **updates: Any) -> dict[str, Any]:
        current = self.ensure(worker_id)
        nxt = transition_management_state(current, state=state, reason=reason, **updates)
        self.ledger.append("management.state", nxt)
        return nxt

    def record(self, record_type: str, value: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(value)
        self.ledger.append(record_type, payload)
        return payload

    def worker_ids(self) -> list[str]:
        found: set[str] = set()
        for entry in self.ledger.all_records():
            record = entry["record"]
            worker_id = record.get("worker_identity") or record.get("worker_id")
            if isinstance(worker_id, str) and worker_id:
                found.add(worker_id)
        return sorted(found)

    def latest(self, record_type: str, worker_id: str, identity_field: str = "worker_identity") -> dict[str, Any] | None:
        latest = None
        for entry in self.ledger.all_records():
            if entry["record_type"] != record_type:
                continue
            record = entry["record"]
            if record.get(identity_field) == worker_id:
                latest = record
        return dict(latest) if latest is not None else None
