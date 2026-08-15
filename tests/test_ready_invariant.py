from __future__ import annotations

import unittest

from mncs_fabric.certify import certify_inventory
from mncs_fabric.conformance import evaluate_conformance, evaluate_ready
from mncs_fabric.desired_state import resolve_desired_state
from mncs_fabric.update_lifecycle import build_update_transaction, reconnect_deadline
from tests.test_inventory import sample_inventory


def _desired(inventory, *, profiles=None, version="0.2.0a21"):
    return resolve_desired_state(
        worker_id=inventory["worker_identity"],
        profiles=profiles or ["mncs-linux-worker"],
        supported_current={"fabric-worker": version},
    )


def _txn(worker_id="worker-a", state="DISCONNECT_EXPECTED", expected="0.2.0a24"):
    return build_update_transaction(
        worker_id=worker_id,
        state=state,
        expected_version=expected,
        previous_version="0.2.0a23",
        artifact_identity=None,
        previous_artifact_identity=None,
        deadline=reconnect_deadline(seconds=30),
        reason="test transaction",
    )


class ReadyInvariantTests(unittest.TestCase):
    def test_missing_conformance_is_verifying_not_ready(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        decision = evaluate_ready(certification=health, conformance=None, inventory=inventory, desired=desired)
        self.assertFalse(decision["ready"])
        self.assertEqual(decision["state"], "VERIFYING")

    def test_stale_conformance_inventory_is_verifying(self) -> None:
        first = sample_inventory(harness="0.1.0")
        second = sample_inventory(harness="0.2.0")
        desired = _desired(second)
        health = certify_inventory(second, profiles=["mncs-linux-worker"])
        stale = evaluate_conformance(_desired(first), first)
        decision = evaluate_ready(certification=health, conformance=stale, inventory=second, desired=desired)
        self.assertEqual(decision["state"], "VERIFYING")
        self.assertIn("inventory:stale-conformance", decision["blockers"])

    def test_mismatched_desired_state_identity_is_verifying(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        other = _desired(inventory, profiles=["mncs-linux-worker", "mncs-build-worker"])
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(certification=health, conformance=conformance, inventory=inventory, desired=other)
        self.assertEqual(decision["state"], "VERIFYING")
        self.assertIn("desired:stale", decision["blockers"])

    def test_stale_inventory_after_certification_is_verifying(self) -> None:
        first = sample_inventory(harness="0.1.0")
        second = sample_inventory(harness="0.2.0")
        desired = _desired(second)
        health = certify_inventory(first, profiles=["mncs-linux-worker"])
        conformance = evaluate_conformance(_desired(second), second)
        decision = evaluate_ready(certification=health, conformance=conformance, inventory=second, desired=desired)
        self.assertEqual(decision["state"], "VERIFYING")
        self.assertIn("inventory:stale-certification", decision["blockers"])

    def test_health_failed_is_quarantined(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        failed = dict(health)
        failed["disposition"] = "FAILED"
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(certification=failed, conformance=conformance, inventory=inventory, desired=desired)
        self.assertEqual(decision["state"], "QUARANTINED")

    def test_health_unknown_is_degraded(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        unknown = dict(health)
        unknown["disposition"] = "UNKNOWN"
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(certification=unknown, conformance=conformance, inventory=inventory, desired=desired)
        self.assertEqual(decision["state"], "DEGRADED")
        self.assertIn("health:UNKNOWN", decision["blockers"])

    def test_blocking_nonconformance_is_degraded(self) -> None:
        inventory = sample_inventory(git=False, harness="0.1.0")
        desired = _desired(inventory, profiles=["mncs-windows-worker"])
        health = certify_inventory(inventory, profiles=["mncs-windows-worker"])
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(certification=health, conformance=conformance, inventory=inventory, desired=desired)
        self.assertEqual(decision["state"], "DEGRADED")
        self.assertTrue(any(item.startswith("conformance:") for item in decision["blockers"]))

    def test_advisory_nonconformance_can_be_ready(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(certification=health, conformance=conformance, inventory=inventory, desired=desired)
        self.assertEqual(decision["state"], "READY")

    def test_unresolved_update_transaction_blocks_ready(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        conformance = evaluate_conformance(desired, inventory)
        decision = evaluate_ready(
            certification=health,
            conformance=conformance,
            inventory=inventory,
            desired=desired,
            transaction=_txn(),
        )
        self.assertEqual(decision["state"], "VERIFYING")
        self.assertIn("update:DISCONNECT_EXPECTED", decision["blockers"])

    def test_legacy_a23_certification_without_conformance_is_not_ready(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = _desired(inventory)
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        decision = evaluate_ready(
            certification=health,
            conformance=None,
            inventory=inventory,
            desired=desired,
            current_inventory_identity=inventory["inventory_identity"],
        )
        self.assertEqual(decision["state"], "VERIFYING")
        self.assertIn("conformance:missing", decision["blockers"])
        self.assertFalse(decision["ready"])
