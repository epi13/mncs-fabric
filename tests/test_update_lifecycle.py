from __future__ import annotations

import unittest

from mncs_fabric.errors import ValidationError
from mncs_fabric.update_lifecycle import (
    build_update_transaction,
    can_transition_update,
    disconnect_is_expected,
    observe_reconnect,
    planned_update_sequence,
    reconnect_deadline,
    transition_update_transaction,
    validate_update_transaction,
    version_matches_expected,
)
from mncs_fabric.fleet_ops import FleetManager
from mncs_fabric.management import ManagementStore
from mncs_fabric.rollout import build_rollout_plan, canary_succeeded, execute_rollout, select_canaries, validate_rollout


class UpdateLifecycleTests(unittest.TestCase):
    def test_expected_disconnect_is_not_an_outage(self) -> None:
        txn = build_update_transaction(
            worker_id="w1",
            state="DISCONNECT_EXPECTED",
            expected_version="0.2.0a24",
            previous_version="0.2.0a23",
            artifact_identity="sha256:" + "a" * 64,
            previous_artifact_identity=None,
            deadline=reconnect_deadline(seconds=30),
            reason="authorized restart",
        )
        checked = validate_update_transaction(txn)
        self.assertTrue(disconnect_is_expected(checked))
        self.assertFalse(disconnect_is_expected(checked, now="2099-01-01T00:00:00Z"))
        self.assertTrue(can_transition_update("DISCONNECT_EXPECTED", "RECONNECTING"))
        nxt = transition_update_transaction(checked, state="RECONNECTING", reason="worker present")
        self.assertEqual(nxt["state"], "RECONNECTING")

    def test_unexpected_outage_has_no_open_transaction(self) -> None:
        self.assertFalse(disconnect_is_expected(None))
        self.assertFalse(version_matches_expected("0.2.0a23", "0.2.0a24"))
        self.assertTrue(version_matches_expected("0.2.0a24", "0.2.0a24"))
        with self.assertRaises(ValidationError):
            build_update_transaction(
                worker_id="w1",
                state="READY",
                expected_version="bad",
                previous_version=None,
                artifact_identity=None,
                previous_artifact_identity=None,
                deadline=reconnect_deadline(),
                reason="nope",
            )

    def test_canary_stops_on_failure(self) -> None:
        plan = validate_rollout(build_rollout_plan(worker_ids=["a", "b", "c"], canary_count=1, stop_on_failure=True))
        self.assertEqual(select_canaries(["a", "b", "c"], canary_count=1), ["a"])
        calls: list[str] = []

        def reconcile(worker_id: str):
            calls.append(worker_id)
            if worker_id == "a":
                return {"receipt": {"disposition": "FAIL", "receipt_identity": "sha256:" + "b" * 64}, "management": {"state": "QUARANTINED"}}
            return {"receipt": {"disposition": "PASS"}, "management": {"state": "READY"}}

        result = execute_rollout(plan, reconcile, apply=True)
        self.assertEqual(result["state"], "STOPPED")
        self.assertEqual(calls, ["a"])
        self.assertTrue(result["results"][0]["failed"])
        self.assertEqual(result["canary_status"], "ROLLOUT_STOPPED")

    def test_planned_sequence_is_legal_and_skips_are_not(self) -> None:
        sequence = planned_update_sequence()
        for current, nxt in zip(sequence, sequence[1:]):
            self.assertTrue(can_transition_update(current, nxt), f"{current} -> {nxt}")
        self.assertFalse(can_transition_update("UPDATE_PLANNED", "DISCONNECT_EXPECTED"))
        self.assertFalse(can_transition_update("UPDATE_APPLIED", "READY"))
        self.assertFalse(can_transition_update("VERSION_VERIFYING", "READY"))

    def test_expected_disconnect_and_reconnect_before_deadline(self) -> None:
        txn = build_update_transaction(
            worker_id="w1",
            state="DISCONNECT_EXPECTED",
            expected_version="0.2.0a24",
            previous_version="0.2.0a23",
            artifact_identity=None,
            previous_artifact_identity=None,
            deadline=reconnect_deadline(seconds=30),
            reason="authorized restart",
        )
        gone = observe_reconnect(txn, connected=False, seen_disconnect=True)
        self.assertEqual(gone["observation"], "EXPECTED_DISCONNECT")
        self.assertEqual(gone["next_state"], "RECONNECTING")
        reconnecting = transition_update_transaction(txn, state="RECONNECTING", reason=gone["reason"])
        back = observe_reconnect(reconnecting, connected=True, seen_disconnect=True, observed_worker_id="w1", observed_version="0.2.0a24")
        self.assertEqual(back["observation"], "RECONNECTED")
        self.assertEqual(back["next_state"], "VERSION_VERIFYING")

    def test_reconnect_timeout_and_wrong_version_are_failures(self) -> None:
        txn = build_update_transaction(
            worker_id="w1",
            state="DISCONNECT_EXPECTED",
            expected_version="0.2.0a24",
            previous_version="0.2.0a23",
            artifact_identity=None,
            previous_artifact_identity=None,
            deadline="2020-01-01T00:00:00Z",
            reason="authorized restart",
        )
        timed = observe_reconnect(txn, connected=False, seen_disconnect=True, now="2026-08-15T00:00:00Z")
        self.assertEqual(timed["observation"], "DEADLINE_EXPIRED")
        self.assertEqual(timed["next_state"], "FAILED")
        still = observe_reconnect(txn, connected=True, seen_disconnect=False, now="2026-08-15T00:00:00Z")
        self.assertEqual(still["observation"], "STILL_CONNECTED")
        verifying = transition_update_transaction(
            build_update_transaction(
                worker_id="w1",
                state="VERSION_VERIFYING",
                expected_version="0.2.0a24",
                previous_version="0.2.0a23",
                artifact_identity=None,
                previous_artifact_identity=None,
                deadline=reconnect_deadline(seconds=30),
                reason="verify",
            ),
            state="VERSION_VERIFYING",
            reason="verify",
        )
        wrong = observe_reconnect(verifying, connected=True, seen_disconnect=True, observed_worker_id="w1", observed_version="0.2.0a23")
        self.assertEqual(wrong["observation"], "WRONG_VERSION")
        self.assertEqual(wrong["next_state"], "ROLLBACK_APPLYING")
        good = observe_reconnect(verifying, connected=True, seen_disconnect=True, observed_worker_id="w1", observed_version="0.2.0a24")
        self.assertEqual(good["next_state"], "CERTIFYING")
        bad_id = observe_reconnect(verifying, connected=True, seen_disconnect=True, observed_worker_id="other", observed_version="0.2.0a24")
        self.assertEqual(bad_id["observation"], "WRONG_IDENTITY")

    def test_second_worker_is_not_reconciled_before_canary_ready(self) -> None:
        plan = validate_rollout(build_rollout_plan(worker_ids=["a", "b"], canary_count=1, stop_on_failure=True))
        calls: list[str] = []

        def pending(worker_id: str):
            calls.append(worker_id)
            return {"restart_required": True, "management": {"state": "MAINTENANCE"}, "update_transaction": {"state": "DISCONNECT_EXPECTED"}}

        result = execute_rollout(plan, pending, apply=True)
        self.assertEqual(calls, ["a"])
        self.assertEqual(result["canary_status"], "CANARY_PENDING")
        self.assertFalse(canary_succeeded({"restart_required": True, "management": {"state": "MAINTENANCE"}}))

        def ready(worker_id: str):
            calls.append(worker_id)
            return {
                "restart_required": False,
                "management": {"state": "READY"},
                "certification": {"disposition": "CERTIFIED"},
                "conformance": {"blocking_failures": []},
                "update_transaction": {"state": "READY"},
                "receipt": {"disposition": "PASS"},
            }

        calls.clear()
        completed = execute_rollout(plan, ready, apply=True)
        self.assertEqual(calls, ["a", "b"])
        self.assertEqual(completed["state"], "COMPLETED")

    def test_failed_health_and_wrong_version_stop_rollout(self) -> None:
        plan = validate_rollout(build_rollout_plan(worker_ids=["a", "b"], canary_count=1, stop_on_failure=True))
        calls: list[str] = []

        def health_fail(worker_id: str):
            calls.append(worker_id)
            return {"management": {"state": "QUARANTINED"}, "certification": {"disposition": "FAILED"}, "receipt": {"disposition": "FAIL"}}

        stopped = execute_rollout(plan, health_fail, apply=True)
        self.assertEqual(calls, ["a"])
        self.assertEqual(stopped["state"], "STOPPED")

        calls.clear()

        def timeout(worker_id: str):
            calls.append(worker_id)
            return {
                "management": {"state": "DEGRADED"},
                "update_transaction": {"state": "FAILED"},
                "observation": {"observation": "DEADLINE_EXPIRED"},
            }

        timed = execute_rollout(plan, timeout, apply=True)
        self.assertEqual(calls, ["a"])
        self.assertEqual(timed["canary_status"], "ROLLOUT_STOPPED")

    def test_stop_on_failure_false_continues_but_is_explicit(self) -> None:
        plan = validate_rollout(build_rollout_plan(worker_ids=["a", "b"], canary_count=1, stop_on_failure=False))
        calls: list[str] = []

        def mixed(worker_id: str):
            calls.append(worker_id)
            if worker_id == "a":
                return {"management": {"state": "QUARANTINED"}, "receipt": {"disposition": "FAIL"}}
            return {
                "management": {"state": "READY"},
                "certification": {"disposition": "CERTIFIED"},
                "conformance": {"blocking_failures": []},
                "receipt": {"disposition": "PASS"},
            }

        result = execute_rollout(plan, mixed, apply=True)
        self.assertEqual(calls, ["a", "b"])
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(result["canary_status"], "CANARY_FAILED")

    def test_controller_restart_recovers_unresolved_transactions_without_reapplying(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            manager = FleetManager(ManagementStore(Path(directory) / "mgmt.jsonl"), controller_id="c")
            txn = build_update_transaction(
                worker_id="w1",
                state="DISCONNECT_EXPECTED",
                expected_version="0.2.0a26",
                previous_version="0.2.0a25",
                artifact_identity=None,
                previous_artifact_identity=None,
                deadline=reconnect_deadline(seconds=30),
                reason="authorized restart",
            )
            manager.store.record("management.update-transaction", txn)
            recovered = manager.recover_unresolved_updates()
            self.assertEqual(len(recovered["unresolved"]), 1)
            self.assertEqual(recovered["unresolved"][0]["action"], "resume_observation")
            self.assertEqual(recovered["unresolved"][0]["state"], "DISCONNECT_EXPECTED")
