from __future__ import annotations

import unittest

from mncs_fabric.errors import ValidationError
from mncs_fabric.update_lifecycle import (
    build_update_transaction,
    can_transition_update,
    disconnect_is_expected,
    reconnect_deadline,
    transition_update_transaction,
    validate_update_transaction,
    version_matches_expected,
)
from mncs_fabric.rollout import build_rollout_plan, execute_rollout, select_canaries, validate_rollout


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
