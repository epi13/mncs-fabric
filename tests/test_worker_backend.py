from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.worker_backend import backend_supports_apply_lease, list_backend_workers


class _WorkersOnlyBackend:
    def workers(self):
        return [{"worker_id": "legacy-backend", "availability": "AVAILABLE"}]

    def refresh_workers(self):
        raise AssertionError("status must not probe a last-known read")

    def close(self) -> None:
        return


class _LeaseAwareBackend:
    def workers(self, *, apply_lease: bool = True):
        return [{"worker_id": "lease-backend", "apply_lease": apply_lease}]


class WorkerBackendContractTests(unittest.TestCase):
    def test_legacy_workers_method_is_accepted(self) -> None:
        backend = _WorkersOnlyBackend()
        self.assertFalse(backend_supports_apply_lease(backend))
        self.assertEqual(list_backend_workers(backend)[0]["worker_id"], "legacy-backend")

    def test_apply_lease_is_passed_when_supported(self) -> None:
        backend = _LeaseAwareBackend()
        self.assertTrue(backend_supports_apply_lease(backend))
        self.assertFalse(list_backend_workers(backend, apply_lease=False)[0]["apply_lease"])

    @unittest.skipUnless(__import__("os").name == "posix", "AF_UNIX persistent transport is POSIX-only")
    def test_service_status_accepts_workers_only_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = ControllerConfig(
                "backend-contract",
                root / "lifecycle.jsonl",
                service_log=root / "service.jsonl",
                socket_path=root / "controller.sock",
                admin_socket_path=root / "controller-admin.sock",
            )
            service = ControllerService(config)
            service._worker_client = _WorkersOnlyBackend()
            thread = threading.Thread(target=service.run, kwargs={"max_seconds": 2.0}, daemon=True)
            thread.start()
            deadline = time.monotonic() + 2.0
            while not config.socket_path_value.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            try:
                status = service.status()
                self.assertEqual(status["fleet"]["observation_mode"], "last-known")
                self.assertEqual(status["fleet"]["workers"][0]["worker_id"], "legacy-backend")
                self.assertTrue(status["service_features"]["last_known_fleet_status"])
                self.assertTrue(status["service_features"]["persistent_fleet_refresh"])
                self.assertTrue(status["service_features"]["classified_fleet_refresh"])
                self.assertTrue(status["service_capabilities"]["operations"]["fleet.refresh"])
            finally:
                service.request_stop()
                thread.join(timeout=3.0)


if __name__ == "__main__":
    unittest.main()
