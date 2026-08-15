"""Desired-state planning, transactional apply, receipts, and Commons companions.

A maintenance transaction is plan-first.  Apply is explicit.  Idempotent
reconcile against a compliant worker yields NO_CHANGES.  Routine success does
not publish Commons objects; unusual discoveries do.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .canonical import attach_identity, is_sha256_identity, verify_identity
from .desired_state import diff_desired_state, validate_desired_state
from .errors import ValidationError
from .inventory import validate_worker_inventory
from .node import utc_now
from .conformance import ADVISORY_PACKAGES
from .providers import apply_action, plan_action_from_change, rollback_action, validate_action

PLAN_SCHEMA = "mncs-fabric.maintenance-plan.v0.1"
RECEIPT_SCHEMA = "mncs-fabric.maintenance-receipt.v0.1"
KNOWLEDGE_SCHEMA = "mncs-fabric.operational-knowledge.v0.1"
PLAN_PHASES = (
    "DISCOVER",
    "PLAN",
    "PREFLIGHT",
    "DRAIN",
    "CAPTURE",
    "APPLY",
    "RESTART",
    "VERIFY",
    "CERTIFY",
    "COMMIT",
)
FAILURE_CLASSES = {
    "NETWORK_FAILURE",
    "AUTH_FAILURE",
    "PACKAGE_FAILURE",
    "VERSION_CONFLICT",
    "SERVICE_FAILURE",
    "VALIDATION_FAILURE",
    "MODEL_FAILURE",
    "DISK_FAILURE",
    "ACTIVE_WORKLOAD",
    "ROLLBACK_FAILURE",
    "UNSUPPORTED_PLATFORM",
    "CONFIGURATION_DRIFT",
    "PRIVILEGE_REQUIRED",
    "HUMAN_REQUIRED",
    "UNSUPPORTED_ACTION",
    "CERTIFICATION_FAILURE",
}


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _optional_identity(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not is_sha256_identity(value):
        raise ValidationError(f"{field} must be a sha256 identity")
    return str(value)


def build_preflight(
    inventory: Mapping[str, Any],
    actions: Iterable[Mapping[str, Any]],
    *,
    active_jobs: int = 0,
    protocol_compatible: bool = True,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    health = inventory.get("health") if isinstance(inventory.get("health"), Mapping) else {}
    checks.append(_check("connectivity", True, None, "inventory was collected from this worker"))
    checks.append(_check("protocol_compatible", protocol_compatible, None if protocol_compatible else "VERSION_CONFLICT", "controller/worker protocol"))
    eligible = health.get("maintenance_eligible") is True and active_jobs == 0
    checks.append(_check("drainable", eligible or active_jobs == 0, "ACTIVE_WORKLOAD" if active_jobs else None, f"active_jobs={active_jobs}"))
    disk = health.get("disk_pressure")
    checks.append(_check("disk", disk != "critical", "DISK_FAILURE" if disk == "critical" else None, f"disk_pressure={disk}"))
    ram = health.get("ram_pressure")
    checks.append(_check("memory", ram != "critical", "DISK_FAILURE" if ram == "critical" else None, f"ram_pressure={ram}"))
    disruptive = any(item.get("disruptive") for item in actions)
    checks.append(_check("active_workload", not (disruptive and active_jobs), "ACTIVE_WORKLOAD" if disruptive and active_jobs else None, "disruptive actions require a drained worker"))
    return checks


def _check(name: str, passed: bool, failure_class: str | None, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "failure_class": failure_class if not passed else None,
        "detail": detail[:256],
    }


def partition_apply_actions(actions: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split worker-applied actions from advisory-only verifies.

    Missing local-harness must stay visible, but it must not be sent to a
    worker apply that would FAIL and roll back a Fabric package update.
    Pre-0.2.0a30 workers treat that verify as a blocking VALIDATION_FAILURE.
    """

    applied: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    for action in actions:
        item = dict(action)
        if item.get("target") in ADVISORY_PACKAGES and item.get("action") in {"inspect", "verify"}:
            advisory.append(item)
        else:
            applied.append(item)
    return applied, advisory


def build_maintenance_plan(
    *,
    worker_id: str,
    desired: Mapping[str, Any],
    inventory: Mapping[str, Any],
    classes: Iterable[str] | None = None,
    controller_id: str = "mncs-fabric-controller",
    active_jobs: int = 0,
) -> dict[str, Any]:
    checked_desired = validate_desired_state(desired, expected_worker_id=worker_id)
    checked_inventory = validate_worker_inventory(inventory, expected_worker_id=worker_id)
    diff = diff_desired_state(checked_desired, checked_inventory, classes=classes)
    actions = [plan_action_from_change(change) for change in diff["changes"]]
    preflight = build_preflight(checked_inventory, actions, active_jobs=active_jobs)
    phases = ["DISCOVER", "PLAN"]
    if actions:
        phases.extend(["PREFLIGHT"])
        if any(item["disruptive"] for item in actions) or checked_desired["policy"]["require_drain"]:
            phases.append("DRAIN")
        phases.extend(["CAPTURE", "APPLY"])
        if any(item["disruptive"] for item in actions):
            phases.append("RESTART")
        phases.extend(["VERIFY"])
        if checked_desired["policy"]["require_certification"]:
            phases.append("CERTIFY")
        phases.append("COMMIT")
    value = {
        "schema_version": PLAN_SCHEMA,
        "worker_identity": worker_id,
        "controller_identity": _text(controller_id, "controller_identity", 128),
        "desired_state_identity": checked_desired["desired_state_identity"],
        "inventory_identity": checked_inventory["inventory_identity"],
        "diff_identity": diff["diff_identity"],
        "change_count": len(actions),
        "actions": actions,
        "preflight": preflight,
        "preflight_passed": all(item["passed"] for item in preflight),
        "phases": phases,
        "require_drain": bool(checked_desired["policy"]["require_drain"] and actions),
        "require_certification": bool(checked_desired["policy"]["require_certification"]),
        "auto_apply_classes": list(checked_desired["policy"]["auto_apply_classes"]),
        "created_at": utc_now(),
        "claim_boundary": "deterministic maintenance plan; not authorization to bypass privilege or attestation",
    }
    return attach_identity(value, "plan_identity")


def validate_maintenance_plan(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != PLAN_SCHEMA:
        raise ValidationError("unsupported maintenance-plan schema")
    required = {
        "schema_version", "worker_identity", "controller_identity", "desired_state_identity",
        "inventory_identity", "diff_identity", "change_count", "actions", "preflight",
        "preflight_passed", "phases", "require_drain", "require_certification",
        "auto_apply_classes", "created_at", "claim_boundary", "plan_identity",
    }
    if set(value) != required or not verify_identity(value, "plan_identity"):
        raise ValidationError("maintenance-plan fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("maintenance plan is bound to another worker")
    if not isinstance(value["actions"], list) or value["change_count"] != len(value["actions"]):
        raise ValidationError("maintenance plan action count is inconsistent")
    [validate_action(item) for item in value["actions"]]
    return dict(value)


def apply_maintenance_plan(
    plan: Mapping[str, Any],
    inventory: Mapping[str, Any],
    *,
    apply: bool,
    force: bool = False,
) -> dict[str, Any]:
    checked = validate_maintenance_plan(plan)
    checked_inventory = validate_worker_inventory(inventory, expected_worker_id=checked["worker_identity"])
    results: list[dict[str, Any]] = []
    if not checked["actions"]:
        return _receipt(checked, checked_inventory, results, disposition="NO_CHANGES", mode="plan" if not apply else "apply")
    if not checked["preflight_passed"] and not force:
        blocked = next(item for item in checked["preflight"] if not item["passed"])
        return _receipt(
            checked,
            checked_inventory,
            results,
            disposition="FAIL",
            mode="plan" if not apply else "apply",
            failure_class=blocked.get("failure_class") or "VALIDATION_FAILURE",
        )
    if not apply:
        for action in checked["actions"]:
            results.append(
                {
                    "action": action["action"],
                    "target": action["target"],
                    "provider": action["provider"],
                    "disposition": "SKIPPED",
                    "failure_class": None,
                    "detail": "plan only",
                    "changed": False,
                    "restart_required": False,
                    "rollback": {"capability": action["rollback"]},
                    "stdout": "",
                    "stderr": "",
                }
            )
        return _receipt(checked, checked_inventory, results, disposition="PASS", mode="plan")
    failed = False
    failure_class = None
    for action in checked["actions"]:
        if action["authorization"] != "none" and action["action"] not in {"inspect", "verify", "rediscover"}:
            result = apply_action(action, checked_inventory)
            results.append(result)
            continue
        result = apply_action(action, checked_inventory)
        results.append(result)
        if result["disposition"] == "FAIL":
            if result.get("target") in ADVISORY_PACKAGES:
                continue
            failed = True
            failure_class = result.get("failure_class") or "VALIDATION_FAILURE"
            break
    if failed:
        rollback_results = []
        for result in reversed(results):
            if result.get("changed"):
                rollback_results.append(rollback_action(result, checked_inventory))
        if any(item.get("disposition") == "FAIL" for item in rollback_results):
            failure_class = "ROLLBACK_FAILURE"
        return _receipt(checked, checked_inventory, results, disposition="FAIL", mode="apply", failure_class=failure_class)
    disposition = "PASS"
    if results and all(item["disposition"] == "SKIPPED" for item in results) and any(item.get("failure_class") for item in results):
        disposition = "UNKNOWN"
    return _receipt(checked, checked_inventory, results, disposition=disposition, mode="apply")


def _receipt(
    plan: Mapping[str, Any],
    inventory: Mapping[str, Any],
    results: list[dict[str, Any]],
    *,
    disposition: str,
    mode: str,
    failure_class: str | None = None,
    certification_identity: str | None = None,
    inventory_after_identity: str | None = None,
    final_management_state: str = "READY",
) -> dict[str, Any]:
    if disposition not in {"PASS", "FAIL", "UNKNOWN", "NO_CHANGES"}:
        raise ValidationError("maintenance receipt disposition is invalid")
    if failure_class is not None and failure_class not in FAILURE_CLASSES:
        raise ValidationError("maintenance receipt failure class is unsupported")
    value = {
        "schema_version": RECEIPT_SCHEMA,
        "operation_id": plan["plan_identity"],
        "worker_identity": plan["worker_identity"],
        "controller_identity": plan["controller_identity"],
        "mode": mode,
        "plan_identity": plan["plan_identity"],
        "desired_state_identity": plan["desired_state_identity"],
        "inventory_before_identity": inventory["inventory_identity"],
        "inventory_after_identity": inventory_after_identity,
        "actions": results,
        "certification_identity": certification_identity,
        "disposition": disposition,
        "failure_class": failure_class,
        "final_management_state": final_management_state,
        "created_at": utc_now(),
        "claim_boundary": "Fabric maintenance receipt; not Commons acceptance or attestation",
    }
    return attach_identity(value, "receipt_identity")


def validate_maintenance_receipt(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != RECEIPT_SCHEMA:
        raise ValidationError("unsupported maintenance-receipt schema")
    required = {
        "schema_version", "operation_id", "worker_identity", "controller_identity",
        "mode", "plan_identity", "desired_state_identity", "inventory_before_identity",
        "inventory_after_identity", "actions", "certification_identity", "disposition",
        "failure_class", "final_management_state", "created_at", "claim_boundary",
        "receipt_identity",
    }
    if set(value) != required or not verify_identity(value, "receipt_identity"):
        raise ValidationError("maintenance-receipt fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("maintenance receipt is bound to another worker")
    if value["disposition"] not in {"PASS", "FAIL", "UNKNOWN", "NO_CHANGES"}:
        raise ValidationError("maintenance receipt disposition is invalid")
    return dict(value)


def complete_receipt(
    plan: Mapping[str, Any],
    inventory: Mapping[str, Any],
    results: list[dict[str, Any]],
    *,
    mode: str,
    disposition: str | None = None,
    failure_class: str | None = None,
    certification_identity: str | None = None,
    inventory_after_identity: str | None = None,
    final_management_state: str = "READY",
) -> dict[str, Any]:
    if disposition is None:
        blocking_failures = [
            item for item in results
            if item.get("disposition") == "FAIL" and item.get("target") not in ADVISORY_PACKAGES
        ]
        if not results and not plan.get("actions"):
            disposition = "NO_CHANGES"
        elif blocking_failures:
            disposition = "FAIL"
            failure_class = blocking_failures[0].get("failure_class") or "VALIDATION_FAILURE"
        elif results and all(item.get("disposition") == "SKIPPED" for item in results):
            disposition = "UNKNOWN" if any(item.get("failure_class") for item in results) else "PASS"
        else:
            disposition = "PASS"
    return _receipt(
        plan,
        inventory,
        results,
        disposition=disposition,
        mode=mode,
        failure_class=failure_class,
        certification_identity=certification_identity,
        inventory_after_identity=inventory_after_identity,
        final_management_state=final_management_state,
    )


def bind_certification(receipt: Mapping[str, Any], certification_identity: str, *, final_state: str, inventory_after_identity: str | None = None) -> dict[str, Any]:
    checked = validate_maintenance_receipt(receipt)
    payload = {key: value for key, value in checked.items() if key != "receipt_identity"}
    payload["certification_identity"] = _optional_identity(certification_identity, "certification_identity")
    payload["final_management_state"] = _text(final_state, "final_management_state", 32)
    if inventory_after_identity is not None:
        payload["inventory_after_identity"] = _optional_identity(inventory_after_identity, "inventory_after_identity")
    return attach_identity(payload, "receipt_identity")


def operational_knowledge(
    inventory: Mapping[str, Any],
    receipt: Mapping[str, Any] | None = None,
    *,
    transaction: Mapping[str, Any] | None = None,
    rollout: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return Commons-shaped companions only for reusable operational discoveries."""

    records: list[dict[str, Any]] = []
    for runtime in inventory.get("runtimes", []):
        if runtime.get("name") != "ollama":
            continue
        manager = runtime.get("service_type")
        if manager in {"systemd-user", "process", "unknown"} and runtime.get("present"):
            records.append(
                _knowledge(
                    kind="Finding",
                    summary=f"Ollama on {inventory.get('worker_identity')} is managed as {manager}, not systemd-system.",
                    rationale="Restart and health operations must rediscover the runtime adapter instead of assuming ollama.service.",
                    evidence=[inventory.get("inventory_identity")],
                )
            )
            records.append(
                _knowledge(
                    kind="Decision",
                    summary="Fabric Ollama operations discover the install/service adapter before restart.",
                    rationale="A missing ollama.service is a valid install mode, not an automatic failure.",
                    evidence=[inventory.get("inventory_identity")],
                )
            )
    supervisor = None
    for service in inventory.get("services", []):
        if service.get("name") == "fabric-worker" and service.get("manager") == "windows-scheduled-task":
            supervisor = service
            break
    if supervisor is not None:
        records.append(
            _knowledge(
                kind="Finding",
                summary=f"Windows worker {inventory.get('worker_identity')} is supervised by a current-user scheduled task, not a native service.",
                rationale="schtasks /Run from a non-interactive OpenSSH session is unreliable; AtLogOn and the watch/launcher path are the supported restart mechanisms.",
                evidence=[inventory.get("inventory_identity")],
            )
        )
        records.append(
            _knowledge(
                kind="Decision",
                summary="Treat Windows OpenSSH job-object restart failure as an expected supervisor limitation, not a worker health failure.",
                rationale="An authorized DISCONNECT_EXPECTED transaction is the protocol observation; host recovery is the scheduled-task watch.",
                evidence=[inventory.get("inventory_identity")],
            )
        )
    if receipt and receipt.get("disposition") == "FAIL" and receipt.get("failure_class"):
        records.append(
            _knowledge(
                kind="Failed Approach",
                summary=f"Maintenance {receipt.get('failure_class')} on {receipt.get('worker_identity')}",
                rationale="Preserve the failing layer so later agents do not retry a known unsafe path blindly.",
                evidence=[receipt.get("receipt_identity")],
            )
        )
    if transaction and transaction.get("state") in {"FAILED", "QUARANTINED"}:
        observation = str(transaction.get("reason") or "")
        kind = "Failed Approach"
        if "version" in observation.lower():
            summary = f"Unexpected reconnect version on {transaction.get('worker_identity')}"
        elif "corrupt" in observation.lower() or "digest" in observation.lower():
            summary = f"Artifact corruption on {transaction.get('worker_identity')}"
        elif "rollback" in observation.lower():
            summary = f"Rollback failure on {transaction.get('worker_identity')}"
        else:
            summary = f"Update transaction {transaction.get('state')} on {transaction.get('worker_identity')}"
        records.append(
            _knowledge(
                kind=kind,
                summary=summary,
                rationale=observation or "Preserve the failed update transaction as typed evidence.",
                evidence=[transaction.get("transaction_identity")],
            )
        )
    if rollout and rollout.get("canary_status") == "CANARY_FAILED":
        records.append(
            _knowledge(
                kind="Failed Approach",
                summary=f"Rollout stopped after canary failure: {rollout.get('reason')}",
                rationale="stop_on_failure must not mutate the remainder after a canary fails post-restart READY checks.",
                evidence=[rollout.get("rollout_identity")],
            )
        )
    platform = str((inventory.get("identity") or {}).get("platform") or "")
    supervisor = None
    for service in inventory.get("services", []):
        if service.get("name") == "fabric-worker":
            supervisor = service
            break
    if platform == "windows" and supervisor and supervisor.get("manager") not in {"windows-scheduled-task", "windows-service"}:
        records.append(
            _knowledge(
                kind="Finding",
                summary=f"Windows worker {inventory.get('worker_identity')} has unsupported persistence {supervisor.get('manager')}",
                rationale="Windows workers require a scheduled-task or service supervisor; other mechanisms are not a Fabric restart contract.",
                evidence=[inventory.get("inventory_identity")],
            )
        )
    return records


def _knowledge(*, kind: str, summary: str, rationale: str, evidence: list[Any]) -> dict[str, Any]:
    value = {
        "schema_version": KNOWLEDGE_SCHEMA,
        "kind": kind,
        "summary": summary[:512],
        "rationale": rationale[:1024],
        "evidence": [item for item in evidence if isinstance(item, str)][:8],
        "created_at": utc_now(),
        "claim_boundary": "Fabric operational companion; Commons ingestion is separate and not implied",
    }
    return attach_identity(value, "knowledge_identity")


def format_plan(plan: Mapping[str, Any]) -> str:
    checked = validate_maintenance_plan(plan)
    lines = [
        f"Worker: {checked['worker_identity']}",
        f"Changes: {checked['change_count']}",
        "Plan:",
    ]
    if not checked["actions"]:
        lines.append("  NO CHANGES REQUIRED")
        return "\n".join(lines)
    step = 1
    if checked["require_drain"]:
        lines.append(f"  {step}. Drain worker")
        step += 1
    for action in checked["actions"]:
        lines.append(f"  {step}. {action['action']} {action['target']} ({action['provider']}, class {action['update_class']})")
        step += 1
    if checked["require_certification"]:
        lines.append(f"  {step}. Run certification")
        step += 1
    lines.append(f"  {step}. Return worker to READY if certification passes")
    return "\n".join(lines)
