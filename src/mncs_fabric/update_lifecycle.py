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
    "ROLLBACK_APPLYING",
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
    "DISCONNECT_EXPECTED": {"RECONNECTING", "VERSION_VERIFYING", "FAILED", "QUARANTINED"},
    "RECONNECTING": {"VERSION_VERIFYING", "FAILED", "QUARANTINED"},
    "VERSION_VERIFYING": {"CERTIFYING", "ROLLBACK_APPLYING", "ROLLED_BACK", "FAILED", "QUARANTINED"},
    "CERTIFYING": {"READY", "ROLLBACK_APPLYING", "ROLLED_BACK", "FAILED", "QUARANTINED"},
    "ROLLBACK_APPLYING": {"RESTART_PENDING", "CERTIFYING", "FAILED", "QUARANTINED"},
    "READY": set(),
    "ROLLED_BACK": {"READY", "QUARANTINED"},
    # A later operator-requested certification may establish that the same
    # enrolled worker is running the exact expected version after an
    # observation deadline expired.  Recovery re-enters at CERTIFYING so it
    # cannot skip version verification, health certification, or conformance.
    "FAILED": {"QUARANTINED", "UPDATE_PLANNED", "CERTIFYING"},
    "QUARANTINED": {"UPDATE_PLANNED"},
}
RECONNECT_OBSERVATIONS = frozenset({
    "AWAITING_DISCONNECT",
    "EXPECTED_DISCONNECT",
    "AWAITING_RECONNECT",
    "RECONNECTED",
    "DEADLINE_EXPIRED",
    "WRONG_IDENTITY",
    "WRONG_VERSION",
    "STILL_CONNECTED",
    "MALFORMED_VERSION",
})
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


def deadline_expired(transaction: Mapping[str, Any], *, now: str | None = None) -> bool:
    checked = validate_update_transaction(transaction)
    stamp = now or utc_now()
    return stamp > checked["deadline"]


def observe_reconnect(
    transaction: Mapping[str, Any],
    *,
    connected: bool,
    seen_disconnect: bool,
    observed_worker_id: str | None = None,
    observed_version: str | None = None,
    observed_artifact_identity: str | None = None,
    now: str | None = None,
    recovery: bool = False,
) -> dict[str, Any]:
    """Classify reconnect evidence without sleeping or mutating ledgers.

    ``recovery=True`` is for controller restart. It does not fabricate a
    disconnect. If the enrolled worker is already present at the expected
    version, observation resumes at version verification.
    """

    checked = validate_update_transaction(transaction)
    expired = deadline_expired(checked, now=now)
    state = checked["state"]
    observation = "AWAITING_DISCONNECT"
    next_state = state
    reason = "no reconnect observation yet"
    present_at_expected = bool(
        connected
        and observed_worker_id in {None, checked["worker_identity"]}
        and version_matches_expected(observed_version, checked["expected_version"])
    )
    if recovery and state in {"DISCONNECT_EXPECTED", "RECONNECTING"} and present_at_expected:
        observation = "RECONNECTED"
        next_state = "VERSION_VERIFYING"
        reason = "controller reconstructed; worker is present at the expected version"
    elif state == "DISCONNECT_EXPECTED":
        if expired and connected and not seen_disconnect:
            observation = "STILL_CONNECTED"
            next_state = "FAILED"
            reason = "worker remained connected after an authorized restart deadline"
        elif expired and not connected:
            observation = "DEADLINE_EXPIRED"
            next_state = "FAILED"
            reason = "worker did not reconnect before the authorized restart deadline"
        elif not connected:
            observation = "EXPECTED_DISCONNECT"
            next_state = "RECONNECTING"
            reason = "authorized disconnect observed"
        elif seen_disconnect and connected:
            observation = "RECONNECTED"
            next_state = "RECONNECTING"
            reason = "worker reconnected after the authorized disconnect"
        else:
            observation = "AWAITING_DISCONNECT"
            next_state = "DISCONNECT_EXPECTED"
            reason = "authorized restart is pending; worker has not yet disconnected"
    elif state == "RECONNECTING":
        if expired and not connected:
            observation = "DEADLINE_EXPIRED"
            next_state = "FAILED"
            reason = "worker did not reconnect before the authorized restart deadline"
        elif not connected:
            observation = "AWAITING_RECONNECT"
            next_state = "RECONNECTING"
            reason = "authorized disconnect observed; waiting for reconnect"
        elif observed_worker_id and observed_worker_id != checked["worker_identity"]:
            observation = "WRONG_IDENTITY"
            next_state = "QUARANTINED"
            reason = "reconnected worker identity does not match the enrolled worker"
        else:
            observation = "RECONNECTED"
            next_state = "VERSION_VERIFYING"
            reason = "worker reconnected; version verification is required"
    elif state == "VERSION_VERIFYING":
        if observed_worker_id and observed_worker_id != checked["worker_identity"]:
            observation = "WRONG_IDENTITY"
            next_state = "QUARANTINED"
            reason = "reconnected worker identity does not match the enrolled worker"
        elif observed_version is not None and parse_fabric_version(observed_version) is None:
            observation = "MALFORMED_VERSION"
            next_state = "FAILED"
            reason = "reconnected worker version is malformed"
        elif not version_matches_expected(observed_version, checked["expected_version"]):
            observation = "WRONG_VERSION"
            next_state = "ROLLBACK_APPLYING"
            reason = (
                f"reconnected version {observed_version!r} does not match expected "
                f"{checked['expected_version']!r}"
            )
        elif (
            checked.get("artifact_identity")
            and observed_artifact_identity
            and observed_artifact_identity != checked["artifact_identity"]
        ):
            observation = "WRONG_VERSION"
            next_state = "ROLLBACK_APPLYING"
            reason = "reconnected artifact identity does not match the update transaction"
        else:
            observation = "RECONNECTED"
            next_state = "CERTIFYING"
            reason = "observed version matches the update transaction"
    else:
        reason = f"reconnect observation is not applicable in {state}"
    return {
        "observation": observation,
        "next_state": next_state,
        "reason": reason,
        "expired": expired,
        "connected": bool(connected),
        "seen_disconnect": bool(seen_disconnect),
        "observed_version": observed_version,
        "observed_worker_id": observed_worker_id,
        "observed_artifact_identity": observed_artifact_identity,
        "expected_version": checked["expected_version"],
        "expected_worker_id": checked["worker_identity"],
        "same_identity": observed_worker_id in {None, checked["worker_identity"]},
        "version_matched": version_matches_expected(observed_version, checked["expected_version"]),
        "recovery": bool(recovery),
    }


def planned_update_sequence() -> tuple[str, ...]:
    return (
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
    )
