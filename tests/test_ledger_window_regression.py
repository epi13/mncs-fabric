from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from mncs_fabric.canonical import attach_identity
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.enrollment import TrustStore
from mncs_fabric.rendezvous import RendezvousCoordinator
from mncs_fabric.store import FabricLedger
from mncs_fabric.work_queue import WorkQueue


class _WindowedLedger:
    """FabricLedger wrapper that enforces bounded-read semantics on records().

    Decision paths must not depend on records(): anything that needs complete
    history has to use all_records().  A small window keeps the truncation
    scenario cheap while preserving the exact failure mode.
    """

    def __init__(self, ledger: FabricLedger, window: int = 2) -> None:
        self._ledger = ledger
        self._window = window
        self.path = ledger.path

    def append(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._ledger.append(*args, **kwargs)

    def records(self, *, record_type: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        entries = self._ledger.all_records(record_type=record_type)
        return entries[-min(limit, self._window):] if limit else []

    def all_records(self, *, record_type: str | None = None) -> list[dict[str, Any]]:
        return self._ledger.all_records(record_type=record_type)


class LedgerWindowRegressionTests(unittest.TestCase):
    def test_trust_lookup_survives_bounded_read_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TrustStore(Path(directory) / "trust.jsonl")
            store.enroll("worker", "window-worker", "sha256:" + "a" * 64)
            windowed = _WindowedLedger(store.ledger)
            store.ledger = windowed  # type: ignore[assignment]
            current = store.lookup("worker", "window-worker")
            self.assertIsNotNone(current)
            self.assertTrue(current["active"])

            store.revoke("worker", "window-worker", reason="test")
            revoked = store.lookup("worker", "window-worker")
            self.assertIsNotNone(revoked)
            self.assertFalse(revoked["active"])
            with self.assertRaises(Exception):
                store.authorize("worker", "window-worker", "sha256:" + "a" * 64)

    def test_rendezvous_generation_survives_bounded_read_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            coordinator = RendezvousCoordinator("controller-window-test", Path(directory) / "rendezvous.jsonl")
            for generation in range(1, 6):
                coordinator.ledger.append(
                    "worker.rendezvous",
                    attach_identity(
                        {
                            "schema_version": "mncs-fabric.rendezvous.v0.1",
                            "worker_id": "window-worker",
                            "session_id": f"session-{generation}",
                            "generation": generation,
                        },
                        "event_identity",
                    ),
                )
            coordinator.ledger = _WindowedLedger(coordinator.ledger)  # type: ignore[assignment]
            self.assertEqual(coordinator._generation("window-worker"), 5)

    def test_work_queue_state_survives_bounded_read_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = WorkQueue(FabricLedger(Path(directory) / "schedule.jsonl"))
            enqueued = queue.enqueue(
                {
                    "idempotency_key": "window-work",
                    "workload_class": "python",
                    "required_capabilities": ["python"],
                    "required_worker_id": "linux",
                },
                client_identity="operator",
            )
            queue.pause()
            queue.ledger = _WindowedLedger(queue.ledger)  # type: ignore[attribute-defined-outside-init]
            self.assertTrue(queue.paused())
            self.assertEqual(queue.latest(enqueued["work_id"])["work_id"], enqueued["work_id"])

    def test_detached_status_survives_bounded_read_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = ControllerConfig(
                "controller-window-test",
                root / "lifecycle.jsonl",
                heartbeat_seconds=0.5,
                socket_path=root / "controller.sock",
                admin_socket_path=root / "controller-admin.sock",
            )
            service = ControllerService(config)
            work_id = "sha256:" + "b" * 64
            service.detached_ledger.append(
                "detached.execution",
                attach_identity(
                    {
                        "schema_version": "mncs-fabric.detached-execution.v0.1",
                        "work_id": work_id,
                        "job_id": "job-window-1",
                        "state": "QUEUED",
                        "attempt": 1,
                        "observed_at": "2026-08-23T00:00:00Z",
                        "reason": None,
                        "result": None,
                    },
                    "event_identity",
                ),
            )
            service._append_detached_event(work_id, "RUNNING", attempt=1)
            service.detached_ledger = _WindowedLedger(service.detached_ledger)  # type: ignore[assignment]
            status = service._detached_status(work_id)
            self.assertEqual(status["job_id"], "job-window-1")
            self.assertEqual(status["state"], "RUNNING")
            batched = service._detached_statuses([work_id])
            self.assertEqual(batched[0]["job_id"], "job-window-1")


if __name__ == "__main__":
    unittest.main()
