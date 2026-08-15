"""Bounded fleet rollout / canary orchestration.

This is sequential per-worker reconcile with stop-on-failure.  It is not a
distributed consensus protocol and does not start disruptive work against
workers that are already busy.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .node import utc_now

ROLLOUT_SCHEMA = "mncs-fabric.fleet-rollout.v0.1"
ROLLOUT_STATES = frozenset({"PLANNED", "IN_PROGRESS", "STOPPED", "COMPLETED", "FAILED"})
CANARY_STATUSES = frozenset({
    "CANARY_PENDING",
    "CANARY_SUCCEEDED",
    "CANARY_FAILED",
    "ROLLOUT_CONTINUING",
    "ROLLOUT_STOPPED",
})
INTERMEDIATE_CANARY_STATES = frozenset({
    "MAINTENANCE",
    "RESTART_PENDING",
    "DISCONNECT_EXPECTED",
    "RECONNECTING",
    "VERSION_VERIFYING",
    "CERTIFYING",
    "DEGRADED",
    "QUARANTINED",
    "VERIFYING",
    "DRAINING",
    "ROLLBACK_APPLYING",
})


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def select_canaries(worker_ids: Iterable[str], *, canary_count: int = 1) -> list[str]:
    ordered = [item for item in worker_ids if isinstance(item, str) and item]
    if canary_count < 1 or canary_count > 16:
        raise ValidationError("canary_count is outside the bounded range")
    return ordered[:canary_count]


def build_rollout_plan(
    *,
    worker_ids: Iterable[str],
    canary_count: int = 1,
    stop_on_failure: bool = True,
    update_class: str = "A",
    reason: str = "operator fleet rollout",
) -> dict[str, Any]:
    workers = [item for item in worker_ids if isinstance(item, str) and item]
    if not workers or len(workers) > 64:
        raise ValidationError("rollout worker set is empty or exceeds the bound")
    canaries = select_canaries(workers, canary_count=canary_count)
    remainder = [item for item in workers if item not in set(canaries)]
    value = {
        "schema_version": ROLLOUT_SCHEMA,
        "state": "PLANNED",
        "canary_count": len(canaries),
        "stop_on_failure": bool(stop_on_failure),
        "update_class": _text(update_class, "update_class", 1),
        "canaries": canaries,
        "remainder": remainder,
        "results": [],
        "canary_status": "CANARY_PENDING",
        "reason": _text(reason, "reason", 512),
        "created_at": utc_now(),
        "claim_boundary": "sequential operator-authorized rollout plan; canary success requires post-restart READY",
    }
    return attach_identity(value, "rollout_identity")


def validate_rollout(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != ROLLOUT_SCHEMA:
        raise ValidationError("unsupported rollout schema")
    required = {
        "schema_version", "state", "canary_count", "stop_on_failure", "update_class",
        "canaries", "remainder", "results", "canary_status", "reason", "created_at",
        "claim_boundary", "rollout_identity",
    }
    if set(value) != required or not verify_identity(value, "rollout_identity"):
        raise ValidationError("rollout fields or identity are invalid")
    if value["state"] not in ROLLOUT_STATES:
        raise ValidationError("rollout state is unsupported")
    if value["canary_status"] not in CANARY_STATUSES:
        raise ValidationError("rollout canary status is unsupported")
    return dict(value)


def deployment_succeeded(outcome: Mapping[str, Any]) -> bool:
    """Package deploy/restart/certify completed; scheduler READY is separate."""

    receipt = outcome.get("receipt") or {}
    certification = outcome.get("certification") or {}
    transaction = outcome.get("update_transaction") or {}
    if outcome.get("restart_required"):
        return False
    if receipt.get("disposition") == "FAIL":
        return False
    if certification and certification.get("disposition") not in {None, "CERTIFIED"}:
        return False
    txn_state = transaction.get("state")
    if txn_state and txn_state not in {"READY", "ROLLED_BACK"}:
        return False
    return True


def canary_succeeded(outcome: Mapping[str, Any]) -> bool:
    """A canary is successful only after post-restart READY, not after apply."""

    management = outcome.get("management") or {}
    transaction = outcome.get("update_transaction") or {}
    certification = outcome.get("certification") or {}
    conformance = outcome.get("conformance") or {}
    receipt = outcome.get("receipt") or {}
    txn_state = transaction.get("state")
    if outcome.get("restart_required"):
        return False
    if receipt.get("disposition") == "FAIL":
        return False
    if management.get("state") != "READY":
        return False
    if management.get("state") in INTERMEDIATE_CANARY_STATES:
        return False
    if txn_state and txn_state not in {"READY", "ROLLED_BACK"}:
        return False
    if certification and certification.get("disposition") != "CERTIFIED":
        return False
    if conformance and conformance.get("blocking_failures"):
        return False
    return True


def canary_failed(outcome: Mapping[str, Any]) -> bool:
    management = (outcome.get("management") or {}).get("state")
    receipt = (outcome.get("receipt") or {}).get("disposition")
    observation = ((outcome.get("observation") or {}).get("observation") if isinstance(outcome.get("observation"), Mapping) else None)
    if receipt == "FAIL":
        return True
    if management == "QUARANTINED":
        return True
    if outcome.get("disposition") in {"FAIL", "FAILED"}:
        return True
    if observation in {"DEADLINE_EXPIRED", "WRONG_VERSION", "WRONG_IDENTITY", "STILL_CONNECTED", "MALFORMED_VERSION"}:
        return True
    txn_state = (outcome.get("update_transaction") or {}).get("state")
    if txn_state in {"FAILED", "QUARANTINED"}:
        return True
    return False


def _record_outcome(worker_id: str, outcome: Mapping[str, Any], *, role: str) -> dict[str, Any]:
    succeeded = canary_succeeded(outcome)
    failed = canary_failed(outcome)
    return {
        "worker_id": worker_id,
        "role": role,
        "failed": bool(failed),
        "succeeded": bool(succeeded),
        "deployment_succeeded": deployment_succeeded(outcome),
        "scheduler_ready": (outcome.get("management") or {}).get("state") == "READY",
        "canary_status": "CANARY_SUCCEEDED" if succeeded else "CANARY_FAILED" if failed else "CANARY_PENDING",
        "management_state": (outcome.get("management") or {}).get("state"),
        "transaction_state": (outcome.get("update_transaction") or {}).get("state"),
        "receipt_identity": (outcome.get("receipt") or {}).get("receipt_identity"),
        "certification_identity": (outcome.get("certification") or {}).get("certification_identity"),
        "conformance_identity": (outcome.get("conformance") or {}).get("conformance_identity"),
        "restart_required": bool(outcome.get("restart_required")),
    }


def execute_rollout(
    plan: Mapping[str, Any],
    reconcile: Callable[[str], Mapping[str, Any]],
    *,
    apply: bool = False,
) -> dict[str, Any]:
    checked = validate_rollout(plan)
    if not apply:
        return checked
    results: list[dict[str, Any]] = []
    state = "IN_PROGRESS"
    canary_status = "CANARY_PENDING"
    for worker_id in list(checked["canaries"]):
        outcome = dict(reconcile(worker_id))
        recorded = _record_outcome(worker_id, outcome, role="canary")
        results.append(recorded)
        if recorded["succeeded"]:
            canary_status = "CANARY_SUCCEEDED"
            continue
        if recorded["failed"]:
            canary_status = "CANARY_FAILED"
            if checked["stop_on_failure"]:
                state = "STOPPED"
                canary_status = "ROLLOUT_STOPPED"
                break
            continue
        canary_status = "CANARY_PENDING"
        if checked["stop_on_failure"]:
            state = "IN_PROGRESS"
            break
    else:
        canary_failed_any = any(item["role"] == "canary" and item["failed"] for item in results)
        canary_pending_any = any(item["role"] == "canary" and not item["succeeded"] and not item["failed"] for item in results)
        if canary_pending_any:
            canary_status = "CANARY_PENDING"
            state = "IN_PROGRESS"
        elif canary_failed_any and checked["stop_on_failure"]:
            canary_status = "ROLLOUT_STOPPED"
            state = "STOPPED"
        else:
            if canary_failed_any:
                canary_status = "CANARY_FAILED"
            else:
                canary_status = "ROLLOUT_CONTINUING"
            for worker_id in list(checked["remainder"]):
                outcome = dict(reconcile(worker_id))
                recorded = _record_outcome(worker_id, outcome, role="remainder")
                results.append(recorded)
                if recorded["failed"] and checked["stop_on_failure"]:
                    state = "STOPPED"
                    canary_status = "ROLLOUT_STOPPED"
                    break
            else:
                if any(item["failed"] for item in results):
                    state = "FAILED"
                    if canary_failed_any:
                        canary_status = "CANARY_FAILED"
                else:
                    state = "COMPLETED"
                    canary_status = "CANARY_SUCCEEDED"
    payload = dict(checked)
    payload["state"] = state
    payload["canary_status"] = canary_status
    payload["results"] = results
    del payload["rollout_identity"]
    return attach_identity(payload, "rollout_identity")
