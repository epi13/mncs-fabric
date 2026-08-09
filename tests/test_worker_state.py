from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.controller import NetworkController
from mncs_fabric.errors import ValidationError
from mncs_fabric.worker import LocalWorker
from mncs_fabric.worker_state import build_liveness_observation, liveness_is_fresh, worker_description_is_fresh
from mncs_fabric.transport import InProcessTransport


class WorkerStateTests(unittest.TestCase):
    def test_liveness_lease_expires_without_mutating_history(self) -> None:
        observation = build_liveness_observation(worker_id="worker", state="AVAILABLE", observed_at="2026-01-01T00:00:00Z", description_identity="sha256:" + "a" * 64, lease_seconds=10)
        self.assertTrue(liveness_is_fresh(observation, now="2026-01-01T00:00:05Z"))
        self.assertFalse(liveness_is_fresh(observation, now="2026-01-01T00:00:11Z"))

    def test_stale_description_is_not_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            description = LocalWorker("worker", bundle, root / "worker.jsonl").description()
            self.assertFalse(worker_description_is_fresh(description, max_age_seconds=0, now="2099-01-01T00:00:00Z"))
            malformed = dict(description)
            malformed["description_identity"] = "sha256:" + "0" * 64
            with self.assertRaises(ValidationError):
                worker_description_is_fresh(malformed)

    def test_refresh_failure_records_unavailable_without_fabricating_execution(self) -> None:
        class Down:
            def request(self, envelope):
                raise ConnectionRefusedError("test worker down")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("worker", frozenset({"python"}), Down())
            with self.assertRaises(ConnectionRefusedError):
                controller.refresh_remote("worker")
            self.assertEqual(controller.worker_state("worker")["availability"], "UNAVAILABLE")
