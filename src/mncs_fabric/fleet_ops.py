"""Controller-side fleet management orchestration.

The management plane is separate from job dispatch.  It talks to workers only
through typed protocol envelopes and records desired-state, plans, receipts,
and certification in an append-only store.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from . import __version__
from .certify import certify_inventory, format_certification, validate_certification
from .desired_state import default_profiles_for_platform, resolve_desired_state, validate_desired_state
from .errors import ProtocolError, ValidationError
from .inventory import validate_worker_inventory
from .maintenance import (
    bind_certification,
    build_maintenance_plan,
    complete_receipt,
    format_plan,
    operational_knowledge,
)
from .management import ManagementStore, management_allows_work, validate_management_state

RequestFn = Callable[[str, dict[str, Any]], dict[str, Any]]


def default_desired_state(worker_id: str, inventory: Mapping[str, Any], *, profiles: Iterable[str] | None = None) -> dict[str, Any]:
    platform_name = str(inventory.get("identity", {}).get("platform") or "linux")
    chosen = list(profiles) if profiles else list(default_profiles_for_platform(platform_name))
    runtime = None
    for item in inventory.get("runtimes", []):
        if item.get("name") == "ollama" and item.get("present"):
            runtime = item
            break
    if runtime is not None and "mncs-inference-worker" not in chosen:
        chosen.append("mncs-inference-worker")
    return resolve_desired_state(
        worker_id=worker_id,
        profiles=chosen,
        supported_current={"fabric-worker": __version__},
    )


def select_workers(workers: Iterable[Mapping[str, Any]], *, profile: str | None = None, platform: str | None = None, worker_id: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
    selected = []
    for worker in workers:
        if worker_id is not None and worker.get("worker_id") != worker_id and worker.get("worker_identity") != worker_id:
            continue
        if platform is not None and str(worker.get("platform") or worker.get("os") or "").lower() != platform.lower():
            continue
        if profile is not None and profile not in (worker.get("profiles") or []):
            continue
        if state is not None and worker.get("management_state") != state and worker.get("availability") != state:
            continue
        selected.append(dict(worker))
    return selected


class FleetManager:
    """Owns desired-state assignment, drain/certify lifecycle, and receipts."""

    def __init__(self, store: ManagementStore, *, controller_id: str) -> None:
        self.store = store
        self.controller_id = controller_id

    def status(self, worker_id: str) -> dict[str, Any]:
        state = self.store.ensure(worker_id)
        desired = self.store.desired_state(worker_id)
        return {
            "worker_id": worker_id,
            "management": state,
            "schedulable": management_allows_work(state["state"]),
            "desired_state_identity": desired.get("desired_state_identity") if desired else None,
            "profiles": list(desired.get("profiles", [])) if desired else [],
        }

    def assign(self, desired: Mapping[str, Any]) -> dict[str, Any]:
        return self.store.assign_desired_state(desired)

    def drain(self, worker_id: str, *, reason: str = "operator drain") -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["active_jobs"] == 0:
            return self.store.set_state(worker_id, state="MAINTENANCE", reason=reason, active_jobs=0)
        return self.store.set_state(worker_id, state="DRAINING", reason=reason)

    def resume(self, worker_id: str, *, reason: str = "operator resume") -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["certification_status"] == "FAILED":
            raise ProtocolError("a worker that failed certification cannot resume to READY")
        if current["state"] == "QUARANTINED" and current["certification_status"] != "CERTIFIED":
            raise ProtocolError("quarantined workers cannot resume to READY without a passing certification")
        status = current["certification_status"] if current["certification_status"] != "NOT_RUN" else "UNKNOWN"
        return self.store.set_state(worker_id, state="READY", reason=reason, certification_status=status)

    def quarantine(self, worker_id: str, *, reason: str) -> dict[str, Any]:
        return self.store.set_state(worker_id, state="QUARANTINED", reason=reason)

    def mark_busy(self, worker_id: str, *, active_jobs: int) -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["state"] in {"DRAINING", "MAINTENANCE", "VERIFYING", "QUARANTINED", "DEGRADED"}:
            return current
        target = "BUSY" if active_jobs else "READY"
        if current["certification_status"] == "FAILED":
            return current
        return self.store.set_state(worker_id, state=target, reason="scheduler observation", active_jobs=active_jobs)

    def complete_drain(self, worker_id: str) -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["state"] == "DRAINING" and current["active_jobs"] == 0:
            return self.store.set_state(worker_id, state="MAINTENANCE", reason="drain complete")
        return current

    def desired_for(self, worker_id: str, inventory: Mapping[str, Any], *, profiles: Iterable[str] | None = None) -> dict[str, Any]:
        if profiles:
            desired = default_desired_state(worker_id, inventory, profiles=profiles)
            self.assign(desired)
            return desired
        existing = self.store.desired_state(worker_id)
        if existing is not None:
            return validate_desired_state(existing, expected_worker_id=worker_id)
        desired = default_desired_state(worker_id, inventory)
        self.assign(desired)
        return desired

    def plan(
        self,
        worker_id: str,
        inventory: Mapping[str, Any],
        *,
        profiles: Iterable[str] | None = None,
        classes: Iterable[str] | None = None,
        active_jobs: int = 0,
    ) -> dict[str, Any]:
        checked = validate_worker_inventory(inventory, expected_worker_id=worker_id)
        desired = self.desired_for(worker_id, checked, profiles=profiles)
        plan = build_maintenance_plan(
            worker_id=worker_id,
            desired=desired,
            inventory=checked,
            classes=classes,
            controller_id=self.controller_id,
            active_jobs=active_jobs,
        )
        self.store.record("management.plan", plan)
        self.store.set_state(
            worker_id,
            state=self.store.ensure(worker_id)["state"],
            reason="plan recorded",
            last_inventory_identity=checked["inventory_identity"],
            last_plan_identity=plan["plan_identity"],
        )
        return plan

    def reconcile(
        self,
        worker_id: str,
        inventory: Mapping[str, Any],
        apply_actions: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
        *,
        apply: bool = False,
        profiles: Iterable[str] | None = None,
        classes: Iterable[str] | None = None,
        active_jobs: int = 0,
        force: bool = False,
        certify: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        plan = self.plan(worker_id, inventory, profiles=profiles, classes=classes, active_jobs=active_jobs)
        if apply and plan["require_drain"]:
            self.drain(worker_id, reason="maintenance drain")
            self.complete_drain(worker_id)
        if apply:
            current = self.store.ensure(worker_id)
            if current["state"] not in {"MAINTENANCE", "DRAINING", "VERIFYING", "DEGRADED"}:
                self.store.set_state(worker_id, state="MAINTENANCE", reason="reconcile apply")
        if not apply:
            receipt = complete_receipt(plan, inventory, [], mode="plan")
            self.store.record("management.receipt", receipt)
            return {
                "plan": plan,
                "receipt": receipt,
                "certification": None,
                "knowledge": operational_knowledge(inventory),
                "management": self.store.state(worker_id),
                "summary": format_plan(plan),
            }
        if not plan["preflight_passed"] and not force:
            blocked = next(item for item in plan["preflight"] if not item["passed"])
            receipt = complete_receipt(plan, inventory, [], mode="apply", disposition="FAIL", failure_class=blocked.get("failure_class") or "VALIDATION_FAILURE")
            self.store.record("management.receipt", receipt)
            self.store.set_state(worker_id, state="DEGRADED", reason="preflight failed", last_receipt_identity=receipt["receipt_identity"])
            return {
                "plan": plan,
                "receipt": receipt,
                "certification": None,
                "knowledge": operational_knowledge(inventory, receipt),
                "management": self.store.state(worker_id),
                "summary": format_plan(plan),
            }
        applied = apply_actions(list(plan["actions"])) if plan["actions"] else []
        receipt = complete_receipt(plan, inventory, applied, mode="apply")
        if receipt["disposition"] == "FAIL":
            self.store.record("management.receipt", receipt)
            self.store.set_state(
                worker_id,
                state="QUARANTINED" if receipt.get("failure_class") == "ROLLBACK_FAILURE" else "DEGRADED",
                reason="maintenance apply failed",
                last_receipt_identity=receipt["receipt_identity"],
            )
            return {
                "plan": plan,
                "receipt": receipt,
                "certification": None,
                "knowledge": operational_knowledge(inventory, receipt),
                "management": self.store.state(worker_id),
                "summary": format_plan(plan),
            }
        self.store.set_state(worker_id, state="VERIFYING", reason="maintenance applied", last_receipt_identity=receipt["receipt_identity"])
        certification = (certify or (lambda _: certify_inventory(inventory)))(inventory)
        validate_certification(certification, expected_worker_id=worker_id)
        final = "READY" if certification["disposition"] == "CERTIFIED" else "QUARANTINED" if certification["disposition"] == "FAILED" else "DEGRADED"
        cert_status = "CERTIFIED" if certification["disposition"] == "CERTIFIED" else "FAILED" if certification["disposition"] == "FAILED" else "UNKNOWN"
        receipt = bind_certification(receipt, certification["certification_identity"], final_state=final)
        self.store.record("management.certification", certification)
        self.store.set_state(
            worker_id,
            state=final,
            reason="certification " + certification["disposition"],
            certification_status=cert_status,
            last_certification_identity=certification["certification_identity"],
            last_receipt_identity=receipt["receipt_identity"],
        )
        self.store.record("management.receipt", receipt)
        return {
            "plan": plan,
            "receipt": receipt,
            "certification": certification,
            "knowledge": operational_knowledge(inventory, receipt),
            "management": self.store.state(worker_id),
            "summary": format_plan(plan) + "\n\n" + format_certification(certification),
        }

    def certify(
        self,
        worker_id: str,
        inventory: Mapping[str, Any],
        *,
        profiles: Iterable[str] | None = None,
        certification: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        checked = validate_worker_inventory(inventory, expected_worker_id=worker_id)
        desired = self.desired_for(worker_id, checked, profiles=profiles)
        result = dict(certification) if certification is not None else certify_inventory(checked, profiles=list(desired["profiles"]))
        validate_certification(result, expected_worker_id=worker_id)
        final = "READY" if result["disposition"] == "CERTIFIED" else "QUARANTINED" if result["disposition"] == "FAILED" else "DEGRADED"
        cert_status = "CERTIFIED" if result["disposition"] == "CERTIFIED" else "FAILED" if result["disposition"] == "FAILED" else "UNKNOWN"
        current = self.store.ensure(worker_id)
        if current["state"] not in {"MAINTENANCE", "VERIFYING", "DEGRADED", "READY", "BUSY"}:
            if current["state"] == "QUARANTINED" and result["disposition"] != "CERTIFIED":
                final = "QUARANTINED"
        self.store.record("management.certification", result)
        self.store.set_state(
            worker_id,
            state=final if result["disposition"] == "CERTIFIED" or current["state"] != "QUARANTINED" else "QUARANTINED",
            reason="certification " + result["disposition"],
            certification_status=cert_status,
            last_inventory_identity=checked["inventory_identity"],
            last_certification_identity=result["certification_identity"],
        )
        return result
