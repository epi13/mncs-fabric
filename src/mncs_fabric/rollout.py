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
        "reason": _text(reason, "reason", 512),
        "created_at": utc_now(),
        "claim_boundary": "sequential operator-authorized rollout plan; not automatic fleet mutation",
    }
    return attach_identity(value, "rollout_identity")


def validate_rollout(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != ROLLOUT_SCHEMA:
        raise ValidationError("unsupported rollout schema")
    required = {
        "schema_version", "state", "canary_count", "stop_on_failure", "update_class",
        "canaries", "remainder", "results", "reason", "created_at", "claim_boundary",
        "rollout_identity",
    }
    if set(value) != required or not verify_identity(value, "rollout_identity"):
        raise ValidationError("rollout fields or identity are invalid")
    if value["state"] not in ROLLOUT_STATES:
        raise ValidationError("rollout state is unsupported")
    return dict(value)


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
    for worker_id in list(checked["canaries"]) + list(checked["remainder"]):
        outcome = dict(reconcile(worker_id))
        failed = outcome.get("disposition") in {"FAIL", "FAILED"} or outcome.get("restart_required") is False and outcome.get("receipt", {}).get("disposition") == "FAIL"
        if "receipt" in outcome and outcome["receipt"].get("disposition") == "FAIL":
            failed = True
        if outcome.get("management", {}).get("state") == "QUARANTINED":
            failed = True
        results.append(
            {
                "worker_id": worker_id,
                "failed": bool(failed),
                "management_state": (outcome.get("management") or {}).get("state"),
                "receipt_identity": (outcome.get("receipt") or {}).get("receipt_identity"),
                "certification_identity": (outcome.get("certification") or {}).get("certification_identity"),
                "conformance_identity": (outcome.get("conformance") or {}).get("conformance_identity"),
                "restart_required": bool(outcome.get("restart_required")),
            }
        )
        if failed and checked["stop_on_failure"]:
            state = "STOPPED"
            break
    else:
        state = "FAILED" if any(item["failed"] for item in results) else "COMPLETED"
        if any(item["failed"] for item in results) and not checked["stop_on_failure"]:
            state = "FAILED"
        elif not any(item["failed"] for item in results):
            state = "COMPLETED"
    payload = dict(checked)
    payload["state"] = state
    payload["results"] = results
    del payload["rollout_identity"]
    return attach_identity(payload, "rollout_identity")
