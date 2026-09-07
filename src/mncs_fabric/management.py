"""Controller-owned worker management state distinct from liveness.

Liveness remains an authenticated contact observation.  Management state is
the operator/controller lifecycle used to keep maintenance and the scheduler
from colliding.  A worker that fails certification does not become READY.

Decision ownership (see ``mncs/fabric_management.mncs``):

- the MNCS module owns the strict transition relation (``_TRANSITIONS``
  without the reflexive closure), the scheduling gate
  (``SCHEDULABLE_STATES``), and the READY/certification invariant. The
  functions below implement those arms exactly;
  ``tests/test_mncs_management_policy.py`` pins every arm mechanically so
  the two cannot drift;
- this Python module additionally owns what MNCS cannot express today:
  ledgers, timestamps, identity hashing, and record validation, plus the
  host-side reflexive closure in ``can_transition`` and the unknown-state
  default in ``management_allows_work``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ProtocolError, ValidationError
from .node import utc_now
from .store import FabricLedger, iter_ledger_records

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
    "READY": frozenset({"BUSY", "DRAINING", "MAINTENANCE", "VERIFYING", "QUARANTINED", "DEGRADED"}),
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
        self._state_cache: dict[str, dict[str, Any]] = {}
        self._desired_cache: dict[str, dict[str, Any]] = {}
        self._latest_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._unscoped_cache: dict[str, dict[str, Any]] = {}
        self._worker_ids_cache: list[str] = []
        self._cache_token: tuple[int, int] | None = None

    def _ensure_cache(self) -> None:
        if not self.ledger.path.exists():
            self._state_cache = {}
            self._desired_cache = {}
            self._latest_cache = {}
            self._unscoped_cache = {}
            self._worker_ids_cache = []
            self._cache_token = None
            return
        stat = self.ledger.path.stat()
        token = (stat.st_size, stat.st_mtime_ns)
        if token != self._cache_token:
            state_cache: dict[str, dict[str, Any]] = {}
            desired_cache: dict[str, dict[str, Any]] = {}
            latest_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
            unscoped_cache: dict[str, dict[str, Any]] = {}
            found: set[str] = set()
            for entry in iter_ledger_records(self.ledger):
                rtype = entry.get("record_type")
                record = entry.get("record", {})
                wid = record.get("worker_identity") or record.get("worker_id")
                if isinstance(wid, str) and wid:
                    found.add(wid)
                if rtype == "management.state" and isinstance(wid, str):
                    state_cache[wid] = record
                elif rtype == "management.desired-state" and isinstance(wid, str):
                    desired_cache[wid] = record
                if rtype and isinstance(wid, str):
                    for id_field in ("worker_identity", "worker_id"):
                        if record.get(id_field) == wid:
                            latest_cache[(str(rtype), wid, id_field)] = record
                if rtype:
                    unscoped_cache[str(rtype)] = record
            self._state_cache = state_cache
            self._desired_cache = desired_cache
            self._latest_cache = latest_cache
            self._unscoped_cache = unscoped_cache
            self._worker_ids_cache = sorted(found)
            self._cache_token = token

    def state(self, worker_id: str) -> dict[str, Any] | None:
        self._ensure_cache()
        latest = self._state_cache.get(worker_id)
        return validate_management_state(latest, expected_worker_id=worker_id) if latest else None

    def ensure(self, worker_id: str, *, reason: str = "initialized") -> dict[str, Any]:
        current = self.state(worker_id)
        if current is not None:
            return current
        created = build_management_state(worker_id=worker_id, state="READY", reason=reason, certification_status="UNKNOWN")
        self.ledger.append("management.state", created)
        self._ensure_cache()
        self._state_cache[worker_id] = created
        if worker_id not in self._worker_ids_cache:
            self._worker_ids_cache = sorted(set(self._worker_ids_cache) | {worker_id})
        return created

    def assign_desired_state(self, desired: Mapping[str, Any]) -> dict[str, Any]:
        from .desired_state import validate_desired_state

        checked = validate_desired_state(desired)
        self.ledger.append("management.desired-state", dict(checked))
        self._ensure_cache()
        wid = checked.get("worker_identity")
        if isinstance(wid, str):
            self._desired_cache[wid] = dict(checked)
            if wid not in self._worker_ids_cache:
                self._worker_ids_cache = sorted(set(self._worker_ids_cache) | {wid})
        return dict(checked)

    def desired_state(self, worker_id: str) -> dict[str, Any] | None:
        self._ensure_cache()
        latest = self._desired_cache.get(worker_id)
        return dict(latest) if latest is not None else None

    def set_state(self, worker_id: str, *, state: str, reason: str, **updates: Any) -> dict[str, Any]:
        current = self.ensure(worker_id)
        nxt = transition_management_state(current, state=state, reason=reason, **updates)
        self.ledger.append("management.state", nxt)
        self._ensure_cache()
        self._state_cache[worker_id] = nxt
        return nxt

    def record(self, record_type: str, value: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(value)
        self.ledger.append(record_type, payload)
        self._cache_token = None
        return payload

    def worker_ids(self) -> list[str]:
        self._ensure_cache()
        return list(self._worker_ids_cache)

    def latest(self, record_type: str, worker_id: str, identity_field: str = "worker_identity") -> dict[str, Any] | None:
        self._ensure_cache()
        latest = self._latest_cache.get((record_type, worker_id, identity_field))
        if latest is not None:
            return dict(latest)
        # Fallback to streaming search if not cached by that identity_field
        for entry in self.ledger.all_records():
            if entry["record_type"] != record_type:
                continue
            record = entry["record"]
            if record.get(identity_field) == worker_id:
                latest = record
        return dict(latest) if latest is not None else None

    def latest_unscoped(self, record_type: str) -> dict[str, Any] | None:
        self._ensure_cache()
        latest = self._unscoped_cache.get(record_type)
        return dict(latest) if latest is not None else None
