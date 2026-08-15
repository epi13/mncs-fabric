"""Controller-side fleet management orchestration.

The management plane is separate from job dispatch.  It talks to workers only
through typed protocol envelopes and records desired-state, plans, receipts,
and certification in an append-only store.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from . import __version__
from .certify import (
    certify_inventory,
    format_certification,
    normalize_certification_evidence,
    validate_certification,
)
from .conformance import UNRESOLVED_UPDATE_STATES, evaluate_conformance, evaluate_ready, validate_conformance
from .desired_state import default_profiles_for_platform, resolve_desired_state, validate_desired_state
from .update_lifecycle import (
    build_update_transaction,
    disconnect_is_expected,
    observe_reconnect,
    reconnect_deadline,
    transition_update_transaction,
    validate_update_transaction,
    version_matches_expected,
)
from .versioning import parse_fabric_version
from .errors import ProtocolError, ValidationError
from .inventory import validate_worker_inventory
from .maintenance import (
    bind_certification,
    build_maintenance_plan,
    complete_receipt,
    format_plan,
    operational_knowledge,
    partition_apply_actions,
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
        conformance = self.store.latest("management.conformance", worker_id)
        transaction = self.store.latest("management.update-transaction", worker_id)
        return {
            "worker_id": worker_id,
            "management": state,
            "schedulable": management_allows_work(state["state"]),
            "desired_state_identity": desired.get("desired_state_identity") if desired else None,
            "profiles": list(desired.get("profiles", [])) if desired else [],
            "conformance_disposition": conformance.get("disposition") if conformance else None,
            "update_transaction": transaction,
            "expected_disconnect": disconnect_is_expected(transaction) if transaction else False,
        }

    def assign(self, desired: Mapping[str, Any]) -> dict[str, Any]:
        return self.store.assign_desired_state(desired)

    def drain(self, worker_id: str, *, reason: str = "operator drain") -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["active_jobs"] == 0:
            return self.store.set_state(worker_id, state="MAINTENANCE", reason=reason, active_jobs=0)
        return self.store.set_state(worker_id, state="DRAINING", reason=reason)

    def _ready_decision(
        self,
        worker_id: str,
        *,
        certification: Mapping[str, Any] | None = None,
        conformance: Mapping[str, Any] | None = None,
        inventory: Mapping[str, Any] | None = None,
        desired: Mapping[str, Any] | None = None,
        management_state: str | None = None,
        completing_update: bool = False,
    ) -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        stored_cert = certification if certification is not None else self.store.latest("management.certification", worker_id)
        stored_conf = conformance if conformance is not None else self.store.latest("management.conformance", worker_id)
        stored_desired = desired if desired is not None else self.store.desired_state(worker_id)
        transaction = self.store.latest("management.update-transaction", worker_id)
        return evaluate_ready(
            certification=stored_cert,
            conformance=stored_conf,
            inventory=inventory,
            desired=stored_desired,
            transaction=transaction,
            management_state=management_state or current["state"],
            current_inventory_identity=None if inventory is not None else current.get("last_inventory_identity"),
            current_desired_state_identity=None if stored_desired is not None else None,
            completing_update=completing_update,
        )

    def resume(self, worker_id: str, *, reason: str = "operator resume") -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        certification = self.store.latest("management.certification", worker_id)
        if current["certification_status"] == "FAILED" or (certification and certification.get("disposition") == "FAILED"):
            raise ProtocolError("a worker that failed certification cannot resume to READY")
        decision = self._ready_decision(worker_id, certification=certification, management_state=current["state"])
        if current["state"] == "QUARANTINED" and not decision["ready"]:
            raise ProtocolError("quarantined workers cannot resume to READY without a passing certification")
        return self.store.set_state(
            worker_id,
            state=decision["state"],
            reason=decision["reason"] if not decision["ready"] else reason,
            certification_status=decision["certification_status"],
        )

    def quarantine(self, worker_id: str, *, reason: str) -> dict[str, Any]:
        return self.store.set_state(worker_id, state="QUARANTINED", reason=reason)

    def mark_busy(self, worker_id: str, *, active_jobs: int) -> dict[str, Any]:
        current = self.store.ensure(worker_id)
        if current["state"] in {"DRAINING", "MAINTENANCE", "VERIFYING", "QUARANTINED", "DEGRADED"}:
            return current
        if current["certification_status"] == "FAILED":
            return current
        if active_jobs:
            return self.store.set_state(worker_id, state="BUSY", reason="scheduler observation", active_jobs=active_jobs)
        decision = self._ready_decision(worker_id, management_state=current["state"])
        return self.store.set_state(
            worker_id,
            state=decision["state"] if decision["ready"] else decision["state"],
            reason="scheduler observation" if decision["ready"] else decision["reason"],
            certification_status=decision["certification_status"],
            active_jobs=0,
        )

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
            checked = validate_desired_state(existing, expected_worker_id=worker_id)
            supported = dict(checked.get("supported_current") or {})
            observed = str((inventory.get("fabric") or {}).get("worker_version") or "")
            if (
                __version__
                and supported.get("fabric-worker") != __version__
                and observed == __version__
            ):
                refreshed = default_desired_state(
                    worker_id,
                    inventory,
                    profiles=list(checked.get("profiles") or []) or profiles,
                )
                self.assign(refreshed)
                return refreshed
            return checked
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
        extra_actions: list[dict[str, Any]] = []
        transaction = None
        if apply and force:
            from .providers import validate_action

            if not any(item.get("provider") == "package.fabric" for item in plan["actions"]):
                extra_actions.append(validate_action({
                    "action": "update",
                    "target": "fabric-worker",
                    "update_class": "A",
                    "provider": "package.fabric",
                    "disruptive": True,
                    "rollback": "partial",
                    "authorization": "operator",
                    "current": str((inventory.get("fabric") or {}).get("worker_version") or "unknown"),
                    "desired": __version__,
                    "reason": "operator requested staged Fabric reinstall",
                }))
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
        actions_to_apply = list(plan["actions"]) + extra_actions
        from .providers import apply_action

        worker_actions, advisory_actions = partition_apply_actions(actions_to_apply)
        if apply and any(item.get("provider") == "package.fabric" for item in worker_actions):
            transaction = self._plan_update_transaction(worker_id, inventory, worker_actions)
            if apply and plan["require_drain"]:
                transaction = self._advance_update(transaction, "DRAINING", "worker drained before Fabric update")
            transaction = self._advance_update(transaction, "UPDATE_APPLYING", "applying staged Fabric artifact")
        applied = apply_actions(worker_actions) if worker_actions else []
        applied.extend(apply_action(action, inventory) for action in advisory_actions)
        receipt = complete_receipt(plan, inventory, applied, mode="apply")
        if receipt["disposition"] == "FAIL" and not any(item.get("restart_required") for item in applied):
            if transaction is not None:
                transaction = self._fail_update(transaction, "maintenance apply failed", quarantined=receipt.get("failure_class") == "ROLLBACK_FAILURE")
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
                "knowledge": operational_knowledge(inventory, receipt, transaction=transaction),
                "management": self.store.state(worker_id),
                "update_transaction": transaction,
                "summary": format_plan(plan),
            }
        if any(item.get("restart_required") for item in applied):
            self.store.record("management.receipt", receipt)
            rollback = applied[-1].get("rollback") if applied and isinstance(applied[-1].get("rollback"), dict) else {}
            previous = str((inventory.get("fabric") or {}).get("worker_version") or "")
            expected = rollback.get("expected_version") or self._expected_version(actions_to_apply, inventory)
            if transaction is None:
                transaction = self._plan_update_transaction(worker_id, inventory, actions_to_apply)
                transaction = self._advance_update(transaction, "UPDATE_APPLYING", "applying authorized restart mutation")
            transaction = self._advance_update(
                transaction,
                "UPDATE_APPLIED",
                "staged Fabric update applied; restart has not been observed",
                receipt_identity=receipt["receipt_identity"],
                artifact_identity=rollback.get("artifact_identity"),
                previous_artifact_identity=rollback.get("previous_artifact_identity"),
                previous_version=rollback.get("previous_version") or previous or None,
                expected_version=expected,
            )
            transaction = self._advance_update(transaction, "RESTART_PENDING", "supervisor restart requested")
            transaction = self._advance_update(
                transaction,
                "DISCONNECT_EXPECTED",
                "authorized Fabric package apply; supervisor restart expected",
                deadline=reconnect_deadline(),
            )
            self.store.set_state(
                worker_id,
                state="MAINTENANCE",
                reason="authorized update applied; disconnect expected until supervisor reconnect",
                last_receipt_identity=receipt["receipt_identity"],
            )
            return {
                "plan": plan,
                "receipt": receipt,
                "certification": None,
                "conformance": None,
                "knowledge": operational_knowledge(inventory, receipt, transaction=transaction),
                "management": self.store.state(worker_id),
                "update_transaction": transaction,
                "summary": format_plan(plan),
                "restart_required": True,
            }
        self.store.set_state(worker_id, state="VERIFYING", reason="maintenance applied", last_receipt_identity=receipt["receipt_identity"])
        raw_evidence = (certify or (lambda current: {"certification": certify_inventory(current), "certified_inventory": current}))(inventory)
        try:
            evidence = normalize_certification_evidence(raw_evidence, fallback_inventory=inventory, expected_worker_id=worker_id)
        except ValidationError as exc:
            receipt = complete_receipt(
                plan,
                inventory,
                applied,
                mode="apply",
                disposition="FAIL",
                failure_class="VALIDATION_FAILURE",
            )
            self.store.record("management.receipt", receipt)
            self.store.set_state(
                worker_id,
                state="VERIFYING",
                reason=f"certification evidence is not bound to one inventory: {exc}",
                last_receipt_identity=receipt["receipt_identity"],
            )
            return {
                "plan": plan,
                "receipt": receipt,
                "certification": None,
                "certified_inventory": None,
                "conformance": None,
                "knowledge": operational_knowledge(inventory, receipt, transaction=transaction),
                "management": self.store.state(worker_id),
                "update_transaction": transaction,
                "summary": format_plan(plan),
            }
        certification = evidence["certification"]
        certified_inventory = evidence["certified_inventory"]
        desired = self.desired_for(worker_id, certified_inventory, profiles=profiles)
        conformance = evaluate_conformance(desired, certified_inventory)
        validate_conformance(conformance, expected_worker_id=worker_id)
        self.store.record("management.certification", certification)
        self.store.record("management.conformance", conformance)
        decision = self._ready_decision(
            worker_id,
            certification=certification,
            conformance=conformance,
            inventory=certified_inventory,
            desired=desired,
        )
        receipt = bind_certification(receipt, certification["certification_identity"], final_state=decision["state"])
        self.store.set_state(
            worker_id,
            state=decision["state"],
            reason=decision["reason"],
            certification_status=decision["certification_status"],
            last_inventory_identity=certified_inventory["inventory_identity"],
            last_certification_identity=certification["certification_identity"],
            last_receipt_identity=receipt["receipt_identity"],
        )
        self.store.record("management.receipt", receipt)
        return {
            "plan": plan,
            "receipt": receipt,
            "certification": certification,
            "certified_inventory": certified_inventory,
            "conformance": conformance,
            "knowledge": operational_knowledge(certified_inventory, receipt, transaction=transaction),
            "management": self.store.state(worker_id),
            "update_transaction": transaction,
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
        raw = {"certification": certification, "certified_inventory": checked} if certification is not None else {
            "certification": certify_inventory(checked, profiles=list(desired["profiles"])),
            "certified_inventory": checked,
        }
        evidence = normalize_certification_evidence(raw, fallback_inventory=checked, expected_worker_id=worker_id)
        result = evidence["certification"]
        certified_inventory = evidence["certified_inventory"]
        desired = self.desired_for(worker_id, certified_inventory, profiles=profiles)
        conformance = evaluate_conformance(desired, certified_inventory)
        validate_conformance(conformance, expected_worker_id=worker_id)
        self.store.record("management.certification", result)
        self.store.record("management.conformance", conformance)
        open_txn = self.store.latest("management.update-transaction", worker_id)
        decision = self._ready_decision(
            worker_id,
            certification=result,
            conformance=conformance,
            inventory=certified_inventory,
            desired=desired,
            completing_update=bool(open_txn and open_txn.get("state") == "CERTIFYING"),
        )
        current = self.store.ensure(worker_id)
        if current["state"] == "QUARANTINED" and result["disposition"] != "CERTIFIED":
            decision = {"state": "QUARANTINED", "certification_status": "FAILED", "reason": "quarantined and health certification did not pass", "ready": False, "blockers": ["quarantine"]}
        self.store.set_state(
            worker_id,
            state=decision["state"],
            reason=decision["reason"],
            certification_status=decision["certification_status"],
            last_inventory_identity=certified_inventory["inventory_identity"],
            last_certification_identity=result["certification_identity"],
        )
        return {
            "certification": result,
            "certified_inventory": certified_inventory,
            "conformance": conformance,
            "management": self.store.state(worker_id),
        }

    def _expected_version(self, actions: Iterable[Mapping[str, Any]], inventory: Mapping[str, Any]) -> str:
        for item in reversed(list(actions)):
            desired = str(item.get("desired") or "")
            if parse_fabric_version(desired) is not None:
                return desired
        current = str((inventory.get("fabric") or {}).get("worker_version") or "")
        return __version__ if parse_fabric_version(__version__) else current or __version__

    def _plan_update_transaction(self, worker_id: str, inventory: Mapping[str, Any], actions: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        previous = str((inventory.get("fabric") or {}).get("worker_version") or "") or None
        if previous is not None and parse_fabric_version(previous) is None:
            previous = None
        transaction = build_update_transaction(
            worker_id=worker_id,
            state="UPDATE_PLANNED",
            expected_version=self._expected_version(actions, inventory),
            previous_version=previous,
            artifact_identity=None,
            previous_artifact_identity=None,
            deadline=reconnect_deadline(),
            reason="operator-authorized Fabric update planned",
        )
        self.store.record("management.update-transaction", transaction)
        return transaction

    def _advance_update(self, transaction: Mapping[str, Any], state: str, reason: str, **updates: Any) -> dict[str, Any]:
        nxt = transition_update_transaction(transaction, state=state, reason=reason, **updates)
        self.store.record("management.update-transaction", nxt)
        return nxt

    def _fail_update(self, transaction: Mapping[str, Any], reason: str, *, quarantined: bool = False) -> dict[str, Any]:
        target = "QUARANTINED" if quarantined else "FAILED"
        current = validate_update_transaction(transaction)
        if current["state"] != target:
            if target == "QUARANTINED" and current["state"] not in {"FAILED", "QUARANTINED"}:
                try:
                    current = self._advance_update(current, "FAILED", reason)
                except ValidationError:
                    pass
            try:
                current = self._advance_update(current, target, reason)
            except ValidationError:
                current = build_update_transaction(
                    worker_id=current["worker_identity"],
                    state=target,
                    expected_version=current["expected_version"],
                    previous_version=current["previous_version"],
                    artifact_identity=current["artifact_identity"],
                    previous_artifact_identity=current["previous_artifact_identity"],
                    deadline=current["deadline"],
                    reason=reason,
                    receipt_identity=current["receipt_identity"],
                    observed_version=current["observed_version"],
                )
                self.store.record("management.update-transaction", current)
        return current

    def observe_update(
        self,
        worker_id: str,
        *,
        connected: bool,
        seen_disconnect: bool,
        inventory: Mapping[str, Any] | None = None,
        now: str | None = None,
        recovery: bool = False,
    ) -> dict[str, Any]:
        transaction = self.store.latest("management.update-transaction", worker_id)
        if transaction is None:
            return {"observation": None, "update_transaction": None, "management": self.store.ensure(worker_id)}
        checked_inventory = validate_worker_inventory(inventory, expected_worker_id=worker_id) if inventory is not None else None
        observed_version = None if checked_inventory is None else (checked_inventory.get("fabric") or {}).get("worker_version")
        observed_id = None if checked_inventory is None else checked_inventory.get("worker_identity")
        result = observe_reconnect(
            transaction,
            connected=connected,
            seen_disconnect=seen_disconnect,
            observed_worker_id=observed_id,
            observed_version=str(observed_version) if observed_version else None,
            now=now,
            recovery=recovery,
        )
        if result["next_state"] != transaction["state"]:
            transaction = self._advance_update(
                transaction,
                result["next_state"],
                result["reason"],
                observed_version=result["observed_version"],
            )
            if result["next_state"] == "QUARANTINED":
                self.store.set_state(worker_id, state="QUARANTINED", reason=result["reason"])
            elif result["next_state"] == "FAILED":
                self.store.set_state(worker_id, state="DEGRADED", reason=result["reason"])
            elif result["next_state"] in {"RECONNECTING", "VERSION_VERIFYING", "CERTIFYING"}:
                self.store.set_state(worker_id, state="VERIFYING", reason=result["reason"])
        return {
            "observation": result,
            "update_transaction": transaction,
            "management": self.store.state(worker_id),
        }

    def verify_update_version(self, worker_id: str, inventory: Mapping[str, Any]) -> dict[str, Any]:
        checked = validate_worker_inventory(inventory, expected_worker_id=worker_id)
        current = self.observe_update(worker_id, connected=True, seen_disconnect=True, inventory=checked)
        transaction = current["update_transaction"]
        if transaction and transaction["state"] == "RECONNECTING":
            current = self.observe_update(worker_id, connected=True, seen_disconnect=True, inventory=checked)
            transaction = current["update_transaction"]
        if transaction and transaction["state"] == "VERSION_VERIFYING":
            current = self.observe_update(worker_id, connected=True, seen_disconnect=True, inventory=checked)
        return current

    def rollback_update(
        self,
        worker_id: str,
        inventory: Mapping[str, Any],
        apply_rollback: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
        *,
        applied_result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        transaction = self.store.latest("management.update-transaction", worker_id)
        if transaction is None:
            raise ProtocolError("rollback requires an open update transaction")
        if transaction["state"] not in {"ROLLBACK_APPLYING", "VERSION_VERIFYING", "CERTIFYING", "FAILED"}:
            raise ProtocolError(f"rollback is not allowed from {transaction['state']}")
        if transaction["state"] != "ROLLBACK_APPLYING":
            transaction = self._advance_update(transaction, "ROLLBACK_APPLYING", "restoring the previous Fabric artifact")
        payload = dict(applied_result or {})
        payload.setdefault("provider", "package.fabric")
        rollback = dict(payload.get("rollback") or {})
        rollback.setdefault("capability", "exact" if transaction.get("previous_artifact_identity") or rollback.get("previous_artifact_path") else "partial")
        rollback.setdefault("previous_version", transaction.get("previous_version"))
        rollback.setdefault("previous_artifact_identity", transaction.get("previous_artifact_identity"))
        rollback.setdefault(
            "previous_artifact_path",
            rollback.get("previous_artifact_path"),
        )
        payload["rollback"] = rollback
        restored = dict(apply_rollback(payload, inventory))
        if restored.get("disposition") != "PASS":
            transaction = self._fail_update(transaction, str(restored.get("detail") or "rollback failed"), quarantined=True)
            self.store.set_state(worker_id, state="QUARANTINED", reason=str(restored.get("detail") or "rollback failed"))
            return {
                "update_transaction": transaction,
                "rollback": restored,
                "management": self.store.state(worker_id),
            }
        previous = transaction.get("previous_version")
        if previous is None or parse_fabric_version(str(previous)) is None:
            transaction = self._fail_update(transaction, "previous version is unknown; rollback cannot be verified", quarantined=True)
            self.store.set_state(worker_id, state="QUARANTINED", reason="previous version is unknown; rollback cannot be verified")
            return {"update_transaction": transaction, "rollback": restored, "management": self.store.state(worker_id)}
        transaction = self._advance_update(
            transaction,
            "RESTART_PENDING",
            "previous artifact restored; rollback restart required",
            expected_version=str(previous),
            artifact_identity=transaction.get("previous_artifact_identity"),
        )
        transaction = self._advance_update(
            transaction,
            "DISCONNECT_EXPECTED",
            "rollback restart expected",
            deadline=reconnect_deadline(),
        )
        self.store.set_state(worker_id, state="MAINTENANCE", reason="rollback applied; disconnect expected")
        return {
            "update_transaction": transaction,
            "rollback": restored,
            "management": self.store.state(worker_id),
            "restart_required": True,
        }

    def complete_update(
        self,
        worker_id: str,
        inventory: Mapping[str, Any],
        *,
        profiles: Iterable[str] | None = None,
        certification: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        verified = self.verify_update_version(worker_id, inventory)
        transaction = verified.get("update_transaction")
        if transaction is not None and transaction["state"] == "ROLLBACK_APPLYING":
            return {**verified, "certification": None, "conformance": None}
        if transaction is not None and transaction["state"] not in {"CERTIFYING", "READY", "ROLLED_BACK"}:
            return {**verified, "certification": None, "conformance": None}
        certified = self.certify(worker_id, inventory, profiles=profiles, certification=certification)
        if transaction is not None and transaction["state"] == "CERTIFYING":
            decision = certified["management"]
            observed = (inventory.get("fabric") or {}).get("worker_version")
            version_ok = version_matches_expected(str(observed) if observed else None, transaction.get("expected_version") or "")
            health = (certified.get("certification") or {}).get("disposition")
            if decision["state"] == "READY" or (version_ok and health == "CERTIFIED" and decision["state"] != "QUARANTINED"):
                rolled_back = transaction.get("expected_version") == transaction.get("previous_version")
                transaction = self._advance_update(
                    transaction,
                    "ROLLED_BACK" if rolled_back and transaction.get("previous_version") else "READY",
                    "update transaction completed after version verification and health certification",
                    observed_version=observed,
                )
                if transaction["state"] == "ROLLED_BACK" and decision["state"] == "READY":
                    self.store.set_state(
                        worker_id,
                        state="READY",
                        reason="rolled back to the previous certified Fabric version",
                        certification_status="CERTIFIED",
                    )
                    certified["management"] = self.store.state(worker_id)
            elif decision["state"] == "QUARANTINED" or health == "FAILED":
                transaction = self._fail_update(transaction, decision.get("reason") or "certification failed", quarantined=True)
            elif not version_ok:
                transaction = self._advance_update(transaction, "ROLLBACK_APPLYING", decision.get("reason") or "observed version does not match the update transaction")
            else:
                transaction = self._fail_update(transaction, decision.get("reason") or "update completion is uncertain")
        certified["update_transaction"] = transaction
        certified["observation"] = verified.get("observation")
        return certified

    MUTATION_RECOVERY_STATES = frozenset({
        "UPDATE_APPLYING",
        "UPDATE_APPLIED",
        "ROLLBACK_APPLYING",
    })

    def classify_unresolved_updates(self) -> dict[str, Any]:
        """Classify ledger-backed update transactions after controller restart."""

        recovered: list[dict[str, Any]] = []
        for worker_id in self.store.worker_ids():
            transaction = self.store.latest("management.update-transaction", worker_id)
            if transaction is None or transaction.get("state") not in UNRESOLVED_UPDATE_STATES:
                continue
            state = transaction["state"]
            if state in {"DISCONNECT_EXPECTED", "RECONNECTING", "VERSION_VERIFYING", "CERTIFYING"}:
                action = "resume_observation"
            elif state == "RESTART_PENDING":
                action = "resume_observation"
            elif state in self.MUTATION_RECOVERY_STATES:
                action = "fail_closed"
            else:
                action = "require_operator"
            recovered.append(
                {
                    "worker_id": worker_id,
                    "state": state,
                    "action": action,
                    "transaction_identity": transaction.get("transaction_identity"),
                    "artifact_identity": transaction.get("artifact_identity"),
                    "previous_artifact_identity": transaction.get("previous_artifact_identity"),
                    "expected_version": transaction.get("expected_version"),
                    "deadline": transaction.get("deadline"),
                    "uncertainty": (
                        "mutation_phase_after_controller_restart"
                        if action == "fail_closed"
                        else "disconnect_not_observed" if action == "resume_observation" else None
                    ),
                }
            )
        return {
            "unresolved": recovered,
            "claim_boundary": "ledger recovery of update transactions; not a second apply and not proof the worker restarted",
        }

    def recover_unresolved_updates(
        self,
        *,
        resume: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Classify, and optionally resume, unresolved update transactions.

        Does not re-apply packages. Mutation-phase transactions stay
        fail-closed until explicit operator recovery.
        """

        classified = self.classify_unresolved_updates()
        if resume is None:
            return classified
        resumed: list[dict[str, Any]] = []
        for item in classified["unresolved"]:
            if item["action"] != "resume_observation":
                resumed.append({**item, "executed": False})
                continue
            outcome = dict(resume(str(item["worker_id"]), item))
            outcome.setdefault("worker_id", item["worker_id"])
            outcome.setdefault("transaction_identity", item["transaction_identity"])
            outcome["executed"] = True
            resumed.append(outcome)
        return {
            **classified,
            "resumed": resumed,
            "claim_boundary": classified["claim_boundary"],
        }

    def resume_update_after_restart(
        self,
        worker_id: str,
        *,
        connected: bool,
        inventory: Mapping[str, Any] | None,
        certify: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Resume observation/certify after controller reconstruction.

        Never re-runs package apply. Does not fabricate a disconnect.
        """

        transaction = self.store.latest("management.update-transaction", worker_id)
        if transaction is None:
            return {
                "worker_id": worker_id,
                "action": "none",
                "state": None,
                "update_transaction": None,
                "management": self.store.ensure(worker_id),
            }
        state = transaction["state"]
        if state in self.MUTATION_RECOVERY_STATES:
            observed = None if inventory is None else (inventory.get("fabric") or {}).get("worker_version")
            if (
                state == "ROLLBACK_APPLYING"
                and inventory is not None
                and version_matches_expected(str(observed) if observed else None, transaction.get("expected_version") or "")
            ):
                transaction = self._advance_update(
                    transaction,
                    "CERTIFYING",
                    "rollback cancelled after controller reconstruction; worker already runs the expected version",
                    observed_version=str(observed) if observed else None,
                )
                completed = self.complete_update(worker_id, inventory)
                return {
                    "worker_id": worker_id,
                    "action": "resumed",
                    "state": (completed.get("update_transaction") or {}).get("state") or transaction["state"],
                    "uncertainty": "rollback_not_executed",
                    "reason": "expected version is already running; rollback was not applied",
                    "update_transaction": completed.get("update_transaction"),
                    "certification": completed.get("certification"),
                    "conformance": completed.get("conformance"),
                    "management": completed.get("management"),
                }
            return {
                "worker_id": worker_id,
                "action": "fail_closed",
                "state": state,
                "uncertainty": "mutation_phase_after_controller_restart",
                "reason": f"update transaction is in {state}; automatic resume would risk a second apply",
                "update_transaction": transaction,
                "management": self.store.ensure(worker_id),
            }
        if state not in {"RESTART_PENDING", "DISCONNECT_EXPECTED", "RECONNECTING", "VERSION_VERIFYING", "CERTIFYING"}:
            return {
                "worker_id": worker_id,
                "action": "require_operator",
                "state": state,
                "update_transaction": transaction,
                "management": self.store.ensure(worker_id),
            }
        if state == "RESTART_PENDING" and not connected:
            transaction = self._advance_update(
                transaction,
                "DISCONNECT_EXPECTED",
                "controller reconstructed; worker is not present after restart-pending",
            )
        observed = self.observe_update(
            worker_id,
            connected=connected,
            seen_disconnect=False,
            inventory=inventory,
            now=now,
            recovery=True,
        )
        transaction = observed.get("update_transaction") or transaction
        if transaction["state"] == "VERSION_VERIFYING" and inventory is not None:
            observed = self.observe_update(
                worker_id,
                connected=True,
                seen_disconnect=False,
                inventory=inventory,
                now=now,
                recovery=True,
            )
            transaction = observed.get("update_transaction") or transaction
        if transaction["state"] == "CERTIFYING" and inventory is not None:
            certification = None
            if certify is not None:
                raw = certify(inventory)
                evidence = normalize_certification_evidence(
                    raw,
                    fallback_inventory=inventory,
                    expected_worker_id=worker_id,
                )
                certification = evidence["certification"]
                inventory = evidence["certified_inventory"]
            completed = self.complete_update(worker_id, inventory, certification=certification)
            return {
                "worker_id": worker_id,
                "action": "resumed",
                "state": (completed.get("update_transaction") or {}).get("state") or transaction["state"],
                "observation": completed.get("observation") or observed.get("observation"),
                "update_transaction": completed.get("update_transaction"),
                "certification": completed.get("certification"),
                "certified_inventory": completed.get("certified_inventory"),
                "conformance": completed.get("conformance"),
                "management": completed.get("management"),
            }
        return {
            "worker_id": worker_id,
            "action": "resumed" if transaction["state"] != state else "resume_observation",
            "state": transaction["state"],
            "observation": observed.get("observation"),
            "update_transaction": transaction,
            "management": observed.get("management"),
        }

    def live_artifact_references(self) -> set[str]:
        """Identities still referenced by current deployments or open work."""

        refs: set[str] = set()
        for worker_id in self.store.worker_ids():
            transaction = self.store.latest("management.update-transaction", worker_id)
            if transaction is None:
                continue
            for key in ("artifact_identity", "previous_artifact_identity"):
                value = transaction.get(key)
                if isinstance(value, str) and value.startswith("sha256:"):
                    refs.add(value)
        rollout = self.store.latest_unscoped("management.rollout")
        if rollout:
            identity = rollout.get("artifact_identity")
            if isinstance(identity, str) and identity.startswith("sha256:"):
                refs.add(identity)
            for item in rollout.get("results") or []:
                if not isinstance(item, dict):
                    continue
                for key in ("artifact_identity", "previous_artifact_identity"):
                    value = item.get(key)
                    if isinstance(value, str) and value.startswith("sha256:"):
                        refs.add(value)
        return refs
