"""Desired-state conformance, distinct from capability health certification.

Health certification asks whether advertised capabilities work.
Conformance asks whether assigned profiles are satisfied.

A missing optional capability is NOT_APPLICABLE.
A missing required capability is NONCONFORMANT and may block READY.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .canonical import attach_identity, verify_identity
from .desired_state import _actual_for, _is_compliant, validate_desired_state
from .errors import ValidationError
from .inventory import inventory_tool, validate_worker_inventory
from .node import utc_now

CONFORMANCE_SCHEMA = "mncs-fabric.conformance-result.v0.1"
CONFORMANCE_DISPOSITIONS = frozenset({"CONFORMANT", "NONCONFORMANT", "UNKNOWN"})
REQUIREMENT_STATUSES = frozenset({
    "PASS",
    "NONCONFORMANT",
    "NOT_APPLICABLE",
    "NOT_INSTALLED",
    "AUTH_REQUIRED",
    "PRIVILEGE_REQUIRED",
    "UNSUPPORTED",
    "UNKNOWN",
})

# Privilege-gated or one-time-human items stay visible as nonconformance
# without making the existing fleet unschedulable.  Missing advisory
# packages must not FAIL a Fabric package apply or trigger rollback.
ADVISORY_PACKAGES = frozenset({"local-harness"})
ADVISORY_TOOLS = frozenset({"gh"})
_ADVISORY_PACKAGES = ADVISORY_PACKAGES
_ADVISORY_TOOLS = ADVISORY_TOOLS
_BUILD_ONLY_TOOLS = frozenset({"gcc", "rustc", "cargo", "joern", "forge"})


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def requirement_blocks_ready(requirement: Mapping[str, Any], *, profiles: Iterable[str]) -> bool:
    """Return whether a failed requirement must keep the worker off READY."""

    kind = requirement.get("kind")
    name = requirement.get("name")
    assigned = set(profiles)
    if kind == "package" and name in _ADVISORY_PACKAGES:
        return False
    if kind == "tool" and name in _ADVISORY_TOOLS:
        return False
    if kind == "tool" and name in _BUILD_ONLY_TOOLS and "mncs-build-worker" not in assigned:
        return False
    if requirement.get("update_class") == "D":
        return False
    return True


def _credential_status(inventory: Mapping[str, Any], name: str) -> str | None:
    for item in inventory.get("credentials", []):
        if item.get("name") == name:
            if item.get("available") is True:
                return "PASS"
            detail = str(item.get("detail") or "")
            if "unauthenticated" in detail:
                return "AUTH_REQUIRED"
            if detail in {"absent", "gh-absent"}:
                return "NOT_INSTALLED"
            return "UNKNOWN"
    return None


def evaluate_conformance(
    desired: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> dict[str, Any]:
    checked_desired = validate_desired_state(desired, expected_worker_id=str(inventory.get("worker_identity")) if inventory.get("worker_identity") else None)
    checked_inventory = validate_worker_inventory(inventory, expected_worker_id=checked_desired["worker_identity"])
    annotated = dict(checked_inventory)
    annotated["_supported_current"] = checked_desired["supported_current"]
    profiles = list(checked_desired["profiles"])
    findings: list[dict[str, Any]] = []
    blocking_failures: list[str] = []
    unknown = False
    for requirement in checked_desired["requirements"]:
        actual, detail = _actual_for(annotated, requirement)
        status = "PASS" if _is_compliant(requirement, actual) else "NONCONFORMANT"
        if actual == "absent":
            status = "NOT_INSTALLED"
        elif actual == "unknown":
            status = "UNKNOWN"
            unknown = True
        if requirement["kind"] == "tool" and requirement["name"] == "gh":
            tool = inventory_tool(checked_inventory, "gh")
            if tool and tool.get("present"):
                cred = _credential_status(checked_inventory, "github-cli")
                if cred == "AUTH_REQUIRED":
                    status = "AUTH_REQUIRED"
                    detail = "gh is present but GitHub authentication is unavailable"
                elif cred == "PASS" and status == "NONCONFORMANT":
                    status = "PASS"
        blocking = requirement_blocks_ready(requirement, profiles=profiles)
        if status in {"NONCONFORMANT", "NOT_INSTALLED"} and requirement["update_class"] in {"B", "D"} and actual == "absent":
            # Absence that Fabric cannot install is still nonconformance.
            pass
        if status in {"NONCONFORMANT", "NOT_INSTALLED", "AUTH_REQUIRED"} and blocking:
            blocking_failures.append(f"{requirement['kind']}:{requirement['name']}")
        if status == "AUTH_REQUIRED" and not blocking:
            # Advisory credential gap.
            pass
        findings.append(
            {
                "kind": requirement["kind"],
                "name": requirement["name"],
                "level": requirement["level"],
                "update_class": requirement["update_class"],
                "blocking": blocking,
                "status": status if status in REQUIREMENT_STATUSES else "UNKNOWN",
                "actual": actual,
                "detail": detail[:256],
            }
        )
    failed = [item for item in findings if item["status"] in {"NONCONFORMANT", "NOT_INSTALLED", "AUTH_REQUIRED"}]
    if unknown and not failed:
        disposition = "UNKNOWN"
    elif failed:
        disposition = "NONCONFORMANT"
    else:
        disposition = "CONFORMANT"
    value = {
        "schema_version": CONFORMANCE_SCHEMA,
        "worker_identity": checked_desired["worker_identity"],
        "inventory_identity": checked_inventory["inventory_identity"],
        "desired_state_identity": checked_desired["desired_state_identity"],
        "profiles": profiles,
        "requirements": findings,
        "blocking_failures": blocking_failures,
        "disposition": disposition,
        "failing_requirement": failed[0]["name"] if failed else None,
        "created_at": utc_now(),
        "claim_boundary": "desired-state conformance versus assigned profiles; not health certification, honesty, or attestation",
    }
    return attach_identity(value, "conformance_identity")


def validate_conformance(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != CONFORMANCE_SCHEMA:
        raise ValidationError("unsupported conformance schema")
    required = {
        "schema_version", "worker_identity", "inventory_identity", "desired_state_identity",
        "profiles", "requirements", "blocking_failures", "disposition", "failing_requirement",
        "created_at", "claim_boundary", "conformance_identity",
    }
    if set(value) != required or not verify_identity(value, "conformance_identity"):
        raise ValidationError("conformance fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("conformance is bound to another worker")
    if value["disposition"] not in CONFORMANCE_DISPOSITIONS:
        raise ValidationError("conformance disposition is invalid")
    if not isinstance(value["requirements"], list) or not isinstance(value["blocking_failures"], list):
        raise ValidationError("conformance requirement lists are invalid")
    return dict(value)


UNRESOLVED_UPDATE_STATES = frozenset({
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
})


def evaluate_ready(
    *,
    certification: Mapping[str, Any] | None,
    conformance: Mapping[str, Any] | None,
    inventory: Mapping[str, Any] | None = None,
    desired: Mapping[str, Any] | None = None,
    transaction: Mapping[str, Any] | None = None,
    management_state: str | None = None,
    current_inventory_identity: str | None = None,
    current_desired_state_identity: str | None = None,
    policy_allows_ready: bool = True,
    completing_update: bool = False,
) -> dict[str, Any]:
    """Single READY predicate used by certify, reconcile, resume, and rollout.

    READY requires current CERTIFIED health, current desired-state
    conformance with no blocking failure, identity binding to the current
    inventory and desired state, no unresolved update transaction, and a
    management policy that allows READY. Missing evidence is VERIFYING,
    not READY.
    """

    def _result(state: str, status: str, reason: str, *blockers: str) -> dict[str, Any]:
        return {
            "state": state,
            "certification_status": status,
            "reason": reason,
            "ready": state == "READY",
            "blockers": [item for item in blockers if item],
        }

    if not policy_allows_ready:
        return _result("MAINTENANCE", "UNKNOWN", "management policy does not allow READY", "policy")

    if transaction is not None:
        txn_state = str(transaction.get("state") or "")
        if txn_state in UNRESOLVED_UPDATE_STATES and not (completing_update and txn_state == "CERTIFYING"):
            return _result(
                "VERIFYING",
                "UNKNOWN",
                f"unresolved update transaction is {txn_state}",
                f"update:{txn_state}",
            )
        if txn_state == "QUARANTINED":
            return _result("QUARANTINED", "FAILED", "update transaction quarantined the worker", "update:QUARANTINED")
        if txn_state == "FAILED":
            return _result("DEGRADED", "UNKNOWN", "update transaction failed", "update:FAILED")

    if certification is None:
        return _result("VERIFYING", "UNKNOWN", "health certification evidence is missing", "certification:missing")

    health = certification.get("disposition")
    if health == "FAILED":
        return _result("QUARANTINED", "FAILED", "health certification failed", "health:FAILED")
    if health != "CERTIFIED":
        return _result("DEGRADED", "UNKNOWN", "health certification is not CERTIFIED", f"health:{health or 'UNKNOWN'}")

    if conformance is None:
        return _result("VERIFYING", "UNKNOWN", "desired-state conformance evidence is missing", "conformance:missing")

    inventory_identity = None
    if inventory is not None:
        inventory_identity = inventory.get("inventory_identity")
    elif current_inventory_identity:
        inventory_identity = current_inventory_identity
    if not inventory_identity:
        return _result("VERIFYING", "CERTIFIED", "current inventory identity is not bound", "inventory:unbound")
    if certification.get("inventory_identity") != inventory_identity:
        return _result("VERIFYING", "CERTIFIED", "health certification is bound to a previous inventory", "inventory:stale-certification")
    if conformance.get("inventory_identity") != inventory_identity:
        return _result("VERIFYING", "CERTIFIED", "conformance is bound to a previous inventory", "inventory:stale-conformance")

    if inventory is not None:
        observed_version = (inventory.get("fabric") or {}).get("worker_version")
        certified_worker = certification.get("worker_identity")
        if certified_worker and inventory.get("worker_identity") != certified_worker:
            return _result("QUARANTINED", "FAILED", "certification is bound to a different worker identity", "identity:mismatch")
        if observed_version and certification.get("observed_version") and certification.get("observed_version") != observed_version:
            return _result("VERIFYING", "CERTIFIED", "worker version changed after certification", "version:changed")

    desired_identity = None
    if desired is not None:
        desired_identity = desired.get("desired_state_identity")
    elif current_desired_state_identity:
        desired_identity = current_desired_state_identity
    if not desired_identity:
        return _result("VERIFYING", "CERTIFIED", "current desired-state identity is not bound", "desired:unbound")
    if conformance.get("desired_state_identity") != desired_identity:
        return _result("VERIFYING", "CERTIFIED", "conformance is bound to a previous desired state", "desired:stale")

    blocking = list(conformance.get("blocking_failures") or [])
    if blocking:
        return _result(
            "DEGRADED",
            "CERTIFIED",
            "certified but desired-state blocking nonconformance: " + str(blocking[0]),
            "conformance:" + str(blocking[0]),
        )
    if conformance.get("disposition") == "UNKNOWN":
        return _result("DEGRADED", "CERTIFIED", "certified but conformance is UNKNOWN", "conformance:UNKNOWN")

    if management_state == "QUARANTINED" and health != "CERTIFIED":
        return _result("QUARANTINED", "FAILED", "quarantined and health certification did not pass", "quarantine")

    return _result("READY", "CERTIFIED", "health certified and blocking conformance satisfied")


def decide_ready_state(
    certification: Mapping[str, Any] | None,
    conformance: Mapping[str, Any] | None,
    *,
    inventory: Mapping[str, Any] | None = None,
    desired: Mapping[str, Any] | None = None,
    transaction: Mapping[str, Any] | None = None,
    management_state: str | None = None,
    current_inventory_identity: str | None = None,
    current_desired_state_identity: str | None = None,
    policy_allows_ready: bool = True,
    completing_update: bool = False,
) -> dict[str, Any]:
    """Compatibility wrapper around evaluate_ready."""

    return evaluate_ready(
        certification=certification,
        conformance=conformance,
        inventory=inventory,
        desired=desired,
        transaction=transaction,
        management_state=management_state,
        current_inventory_identity=current_inventory_identity,
        current_desired_state_identity=current_desired_state_identity,
        policy_allows_ready=policy_allows_ready,
        completing_update=completing_update,
    )
