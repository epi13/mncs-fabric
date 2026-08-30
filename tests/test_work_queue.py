from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mncs_fabric.availability import evaluate_availability, window_contains
from mncs_fabric.store import FabricLedger
from mncs_fabric.work_queue import WorkQueue
from datetime import time


POLICY = {
    "schema_version": "mncs-fabric.availability-policy.v0.1",
    "timezone": "UTC",
    "workers": {
        "linux": {
            "windows": [{"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], "start": "22:00", "end": "10:00"}],
            "allowed_workload_classes": ["python", "inference"],
        },
        "windows": {
            "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "02:00", "end": "16:00"}],
            "allowed_workload_classes": ["python", "inference"],
        },
    },
}


class AvailabilityAndQueueTests(unittest.TestCase):
    def test_overnight_window_and_outside_window(self) -> None:
        inside = datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc)  # Friday 02:00 UTC
        outside = datetime(2026, 8, 14, 15, 0, tzinfo=timezone.utc)  # Friday 15:00 UTC
        self.assertTrue(evaluate_availability(POLICY, "linux", now=inside)["eligible"])
        self.assertFalse(evaluate_availability(POLICY, "linux", now=outside)["eligible"])
        self.assertEqual(
            evaluate_availability(POLICY, "linux", now=outside)["reason"], "OUTSIDE_WINDOW"
        )
        self.assertTrue(window_contains(time(22, 0), time(10, 0), time(2, 0)))
        self.assertFalse(window_contains(time(22, 0), time(10, 0), time(15, 0)))

    def test_tick_dispatches_inside_window_and_holds_outside(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = WorkQueue(FabricLedger(Path(directory) / "schedule.jsonl"))
            first = queue.enqueue(
                {
                    "idempotency_key": "nightly-tests",
                    "recurrence_identity": "nightly-tests",
                    "workload_class": "python",
                    "required_capabilities": ["python"],
                    "required_worker_id": "linux",
                },
                client_identity="operator",
            )
            duplicate = queue.enqueue(
                {
                    "idempotency_key": "nightly-tests",
                    "recurrence_identity": "nightly-tests",
                    "workload_class": "python",
                    "required_capabilities": ["python"],
                    "required_worker_id": "linux",
                },
                client_identity="operator",
            )
            self.assertEqual(first["work_id"], duplicate["work_id"])
            workers = [
                {"worker_id": "linux", "availability": "AVAILABLE", "capabilities": ["python"]},
                {"worker_id": "windows", "availability": "AVAILABLE", "capabilities": ["python"]},
            ]
            held = queue.tick(
                policy=POLICY,
                workers=workers,
                now=datetime(2026, 8, 14, 15, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(held["dispatched"], [])
            self.assertEqual(held["held"][0]["work_id"], first["work_id"])
            inside = queue.tick(
                policy=POLICY,
                workers=workers,
                now=datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(inside["dispatched"][0]["worker_id"], "linux")
            self.assertEqual(queue.queued(), [])

    def test_incompatible_node_and_operator_pause(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = WorkQueue(FabricLedger(Path(directory) / "schedule.jsonl"))
            work = queue.enqueue(
                {
                    "idempotency_key": "gpu-job",
                    "workload_class": "inference",
                    "required_capabilities": ["cuda"],
                },
                client_identity="operator",
            )
            workers = [{"worker_id": "linux", "availability": "AVAILABLE", "capabilities": ["python"]}]
            result = queue.tick(
                policy=POLICY,
                workers=workers,
                now=datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(result["held"][0]["work_id"], work["work_id"])
            queue.pause()
            paused = queue.tick(
                policy=POLICY,
                workers=[
                    {"worker_id": "linux", "availability": "AVAILABLE", "capabilities": ["cuda"]}
                ],
                now=datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc),
            )
            self.assertTrue(paused["paused"])
            self.assertEqual(paused["dispatched"], [])
            queue.resume()
            dispatched = queue.tick(
                policy=POLICY,
                workers=[
                    {"worker_id": "linux", "availability": "AVAILABLE", "capabilities": ["cuda"]}
                ],
                now=datetime(2026, 8, 14, 2, 0, tzinfo=timezone.utc),
            )
            self.assertEqual(dispatched["dispatched"][0]["work_id"], work["work_id"])

    def test_restart_preserves_queued_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule.jsonl"
            first = WorkQueue(FabricLedger(path))
            submitted = first.enqueue(
                {"idempotency_key": "survives-restart", "required_capabilities": ["python"]},
                client_identity="operator",
            )
            restarted = WorkQueue(FabricLedger(path))
            self.assertEqual(restarted.queued()[0]["work_id"], submitted["work_id"])


if __name__ == "__main__":
    unittest.main()
