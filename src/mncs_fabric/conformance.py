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
# without making the existing fleet unschedulable.
_ADVISORY_PACKAGES = frozenset({"local-harness"})
_ADVISORY_TOOLS = frozenset({"gh"})
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


def decide_ready_state(certification: Mapping[str, Any], conformance: Mapping[str, Any]) -> dict[str, str]:
    """Map health + conformance onto a management state.  Does not mutate ledgers."""

    health = certification.get("disposition")
    if health == "FAILED":
        return {"state": "QUARANTINED", "certification_status": "FAILED", "reason": "health certification failed"}
    if health != "CERTIFIED":
        return {"state": "DEGRADED", "certification_status": "UNKNOWN", "reason": "health certification is not CERTIFIED"}
    blocking = list(conformance.get("blocking_failures") or [])
    if blocking:
        return {
            "state": "DEGRADED",
            "certification_status": "CERTIFIED",
            "reason": "certified but desired-state blocking nonconformance: " + blocking[0],
        }
    if conformance.get("disposition") == "UNKNOWN":
        return {"state": "DEGRADED", "certification_status": "CERTIFIED", "reason": "certified but conformance is UNKNOWN"}
    return {"state": "READY", "certification_status": "CERTIFIED", "reason": "health certified and blocking conformance satisfied"}
