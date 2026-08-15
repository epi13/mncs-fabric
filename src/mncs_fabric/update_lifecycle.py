"""Explicit Fabric update/restart transactions.

An authorized restart is not an unexplained outage.  The controller records
the expected disconnect, version, artifact, and deadline separately from
liveness.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .node import utc_now
from .versioning import parse_fabric_version

UPDATE_TRANSACTION_SCHEMA = "mncs-fabric.update-transaction.v0.1"
UPDATE_STATES = (
    "UPDATE_PLANNED",
    "DRAINING",
    "UPDATE_APPLYING",
    "UPDATE_APPLIED",
    "RESTART_PENDING",
    "DISCONNECT_EXPECTED",
    "RECONNECTING",
    "VERSION_VERIFYING",
    "CERTIFYING",
    "READY",
    "ROLLED_BACK",
    "FAILED",
    "QUARANTINED",
)
_TRANSITIONS = {
    "UPDATE_PLANNED": {"DRAINING", "UPDATE_APPLYING", "FAILED"},
    "DRAINING": {"UPDATE_APPLYING", "FAILED"},
    "UPDATE_APPLYING": {"UPDATE_APPLIED", "FAILED", "QUARANTINED"},
    "UPDATE_APPLIED": {"RESTART_PENDING", "FAILED"},
    "RESTART_PENDING": {"DISCONNECT_EXPECTED", "FAILED"},
    "DISCONNECT_EXPECTED": {"RECONNECTING", "FAILED", "QUARANTINED"},
    "RECONNECTING": {"VERSION_VERIFYING", "FAILED", "QUARANTINED"},
    "VERSION_VERIFYING": {"CERTIFYING", "ROLLED_BACK", "FAILED", "QUARANTINED"},
    "CERTIFYING": {"READY", "ROLLED_BACK", "FAILED", "QUARANTINED"},
    "READY": set(),
    "ROLLED_BACK": {"READY", "QUARANTINED"},
    "FAILED": {"QUARANTINED", "UPDATE_PLANNED"},
    "QUARANTINED": {"UPDATE_PLANNED"},
}
DEFAULT_RECONNECT_SECONDS = 120.0
MAX_RECONNECT_SECONDS = 600.0


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


def build_update_transaction(
    *,
    worker_id: str,
    state: str,
    expected_version: str,
    previous_version: str | None,
    artifact_identity: str | None,
    previous_artifact_identity: str | None,
    deadline: str,
    reason: str,
    receipt_identity: str | None = None,
    observed_version: str | None = None,
) -> dict[str, Any]:
    if state not in UPDATE_STATES:
        raise ValidationError("update transaction state is unsupported")
    if parse_fabric_version(expected_version) is None:
        raise ValidationError("expected_version is malformed")
    if previous_version is not None and parse_fabric_version(previous_version) is None:
        raise ValidationError("previous_version is malformed")
    if observed_version is not None and parse_fabric_version(observed_version) is None:
        raise ValidationError("observed_version is malformed")
    value = {
        "schema_version": UPDATE_TRANSACTION_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "state": state,
        "expected_version": expected_version,
        "previous_version": previous_version,
        "observed_version": observed_version,
        "artifact_identity": artifact_identity,
        "previous_artifact_identity": previous_artifact_identity,
        "receipt_identity": receipt_identity,
        "deadline": deadline,
        "reason": _text(reason, "reason", 512),
        "updated_at": utc_now(),
        "claim_boundary": "authorized update/restart transaction; not liveness or host honesty",
    }
    return attach_identity(value, "transaction_identity")


def validate_update_transaction(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != UPDATE_TRANSACTION_SCHEMA:
        raise ValidationError("unsupported update transaction schema")
    required = {
        "schema_version", "worker_identity", "state", "expected_version", "previous_version",
        "observed_version", "artifact_identity", "previous_artifact_identity", "receipt_identity",
        "deadline", "reason", "updated_at", "claim_boundary", "transaction_identity",
    }
    if set(value) != required or not verify_identity(value, "transaction_identity"):
        raise ValidationError("update transaction fields or identity are invalid")
    if expected_worker_id is not None and value["worker_identity"] != expected_worker_id:
        raise ValidationError("update transaction is bound to another worker")
    if value["state"] not in UPDATE_STATES:
        raise ValidationError("update transaction state is unsupported")
    _optional_identity(value["artifact_identity"], "artifact_identity")
    _optional_identity(value["previous_artifact_identity"], "previous_artifact_identity")
    _optional_identity(value["receipt_identity"], "receipt_identity")
    return dict(value)


def can_transition_update(current: str, target: str) -> bool:
    if current == target:
        return True
    return target in _TRANSITIONS.get(current, set())


def transition_update_transaction(current: Mapping[str, Any], *, state: str, reason: str, **updates: Any) -> dict[str, Any]:
    checked = validate_update_transaction(current)
    if not can_transition_update(checked["state"], state):
        raise ValidationError(f"update transaction transition {checked['state']} -> {state} is not allowed")
    payload = {
        "worker_id": checked["worker_identity"],
        "state": state,
        "expected_version": updates.get("expected_version", checked["expected_version"]),
        "previous_version": updates.get("previous_version", checked["previous_version"]),
        "artifact_identity": updates.get("artifact_identity", checked["artifact_identity"]),
        "previous_artifact_identity": updates.get("previous_artifact_identity", checked["previous_artifact_identity"]),
        "deadline": updates.get("deadline", checked["deadline"]),
        "reason": reason,
        "receipt_identity": updates.get("receipt_identity", checked["receipt_identity"]),
        "observed_version": updates.get("observed_version", checked["observed_version"]),
    }
    return build_update_transaction(**payload)


def reconnect_deadline(*, seconds: float = DEFAULT_RECONNECT_SECONDS) -> str:
    if not 1.0 <= seconds <= MAX_RECONNECT_SECONDS:
        raise ValidationError("reconnect deadline is outside the bounded range")
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return when.isoformat().replace("+00:00", "Z")


def disconnect_is_expected(transaction: Mapping[str, Any] | None, *, now: str | None = None) -> bool:
    if transaction is None:
        return False
    checked = validate_update_transaction(transaction)
    if checked["state"] not in {"RESTART_PENDING", "DISCONNECT_EXPECTED", "RECONNECTING"}:
        return False
    stamp = now or utc_now()
    return stamp <= checked["deadline"]


def version_matches_expected(observed: str | None, expected: str) -> bool:
    left = parse_fabric_version(observed)
    right = parse_fabric_version(expected)
    return left is not None and right is not None and left == right
