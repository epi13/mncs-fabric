from __future__ import annotations

import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.api import FabricClient
from mncs_fabric.controller import NetworkController
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.errors import TransportTimeoutError
from mncs_fabric.fleet_refresh import (
    annotate_refresh,
    classify_refresh_outcome,
    operation_deadline_seconds,
    remaining_request_seconds,
)
from mncs_fabric.service_transport import SERVICE_REQUEST_TTL_SECONDS
from mncs_fabric.transport import InProcessTransport
from mncs_fabric.worker import LocalWorker
from mncs_fabric.worker_state import build_liveness_observation


class _TimeoutTransport:
    def __init__(self, delay: float = 0.3) -> None:
        self.delay = delay
        self.calls = 0

    def request(self, envelope: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        del envelope
        self.calls += 1
        wait = self.delay if timeout is None else min(self.delay, max(timeout, 0.0))
        time.sleep(wait)
        if timeout is not None and self.delay > timeout:
            raise TransportTimeoutError(f"Fabric control response timed out after {timeout:.3f}s")
        raise TransportTimeoutError("Fabric control response timed out")


class _DownTransport:
    def request(self, envelope: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        del envelope, timeout
        raise ConnectionRefusedError("test worker down")


class _IgnoreDeadlineTransport(_TimeoutTransport):
    def request(self, envelope: dict[str, object], *, timeout: float | None = None) -> dict[str, object]:
        del envelope, timeout
        self.calls += 1
        time.sleep(self.delay)
        raise TransportTimeoutError("worker ignored the per-request deadline")


def _local_worker(root: Path, worker_id: str) -> LocalWorker:
    bundle = root / f"{worker_id}-bundle"
    bundle.mkdir()
    return LocalWorker(worker_id, bundle, root / f"{worker_id}.jsonl")


class FleetRefreshClassificationTests(unittest.TestCase):
    def test_outcome_distinguishes_complete_partial_and_unknown(self) -> None:
        self.assertEqual(classify_refresh_outcome([{"refresh": "PASS"}, {"refresh": "PASS"}]), "PASS")
        self.assertEqual(
            classify_refresh_outcome([{"refresh": "PASS"}, {"refresh": "UNAVAILABLE"}]),
            "PASS",
        )
        self.assertEqual(
            classify_refresh_outcome([{"refresh": "PASS"}, {"refresh": "TIMEOUT"}]),
            "PARTIAL",
        )
        self.assertEqual(
            classify_refresh_outcome([{"refresh": "TIMEOUT"}, {"refresh": "TIMEOUT"}]),
            "UNKNOWN",
        )

    def test_timeout_annotation_keeps_last_known_availability(self) -> None:
        annotated = annotate_refresh(
            {"worker_id": "worker-a", "availability": "AVAILABLE", "last_observed_at": "2026-01-01T00:00:00Z"},
            status="TIMEOUT",
            deadline_fired="worker",
        )
        self.assertEqual(annotated["availability"], "AVAILABLE")
        self.assertEqual(annotated["refresh"], "TIMEOUT")
        self.assertEqual(annotated["deadline_fired"], "worker")


class NetworkFleetRefreshTests(unittest.TestCase):
    def test_fast_worker_refresh_replaces_stale_observation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            worker = _local_worker(root, "fast-worker")
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("fast-worker", worker.capabilities(), InProcessTransport(worker))
            controller.remote_liveness["fast-worker"] = build_liveness_observation(
                worker_id="fast-worker",
                state="AVAILABLE",
                observed_at="2020-01-01T00:00:00Z",
                description_identity=None,
            )
            report = controller.refresh_fleet()
            self.assertEqual(report["outcome"], "PASS")
            state = report["workers"][0]
            self.assertEqual(state["refresh"], "PASS")
            self.assertEqual(state["availability"], "AVAILABLE")
            self.assertGreater(state["last_observed_at"], "2020-01-01T00:00:00Z")
            self.assertEqual(state["worker_service_version"], worker.description()["worker_service_version"])
            self.assertEqual(state["description_captured_at"], state["description"]["captured_at"])

    def test_timeout_retains_last_known_and_does_not_mark_unavailable(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            worker = _local_worker(root, "known-worker")
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("known-worker", worker.capabilities(), InProcessTransport(worker))
            controller.refresh_remote("known-worker")
            observed = controller.worker_state("known-worker")["last_observed_at"]
            controller.remote_workers["known-worker"] = (
                _TimeoutTransport(delay=0.3),
                controller.remote_workers["known-worker"][1],
            )
            report = controller.refresh_fleet(per_worker_deadline=0.05)
            state = report["workers"][0]
            self.assertEqual(state["refresh"], "TIMEOUT")
            self.assertEqual(state["deadline_fired"], "worker")
            self.assertEqual(state["availability"], "AVAILABLE")
            self.assertEqual(controller.worker_state("known-worker", apply_lease=False)["availability"], "AVAILABLE")
            self.assertEqual(controller.worker_state("known-worker", apply_lease=False)["last_observed_at"], observed)

    def test_unreachable_worker_is_unavailable_not_timeout(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("down-worker", frozenset({"python"}), _DownTransport())
            report = controller.refresh_fleet()
            state = report["workers"][0]
            self.assertEqual(state["refresh"], "UNAVAILABLE")
            self.assertEqual(state["availability"], "UNAVAILABLE")
            self.assertIsNone(state.get("deadline_fired"))

    def test_concurrent_refresh_keeps_fast_worker_when_peer_is_slow(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            fast = _local_worker(root, "b-fast")
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("a-slow", frozenset({"python"}), _TimeoutTransport(delay=0.4))
            controller.register_remote("b-fast", fast.capabilities(), InProcessTransport(fast))
            started = time.monotonic()
            report = controller.refresh_fleet(operation_deadline=0.25, per_worker_deadline=0.2)
            elapsed = time.monotonic() - started
            by_id = {item["worker_id"]: item for item in report["workers"]}
            self.assertEqual(report["outcome"], "PARTIAL")
            self.assertEqual(by_id["b-fast"]["refresh"], "PASS")
            self.assertEqual(by_id["a-slow"]["refresh"], "TIMEOUT")
            self.assertLess(elapsed, 0.35)

    def test_operation_deadline_is_named_when_it_fires_first(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("slow-worker", frozenset({"python"}), _IgnoreDeadlineTransport(delay=0.4))
            report = controller.refresh_fleet(operation_deadline=0.08)
            state = report["workers"][0]
            self.assertEqual(state["refresh"], "TIMEOUT")
            self.assertEqual(state["deadline_fired"], "operation")
            self.assertIn("operation deadline", state["refresh_diagnostic"])

    def test_retry_is_idempotent_and_does_not_duplicate_registered_workers(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            worker = _local_worker(root, "retry-worker")
            controller = NetworkController("controller", root / "controller.jsonl")
            controller.register_remote("retry-worker", worker.capabilities(), InProcessTransport(worker))
            first = controller.refresh_fleet()
            second = controller.refresh_fleet()
            self.assertEqual(first["outcome"], "PASS")
            self.assertEqual(second["outcome"], "PASS")
            self.assertEqual(len(controller.remote_workers), 1)
            self.assertNotEqual(first["refresh_generation"], second["refresh_generation"])

    def test_restore_last_known_survives_controller_reconstruction(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            worker = _local_worker(root, "restored-worker")
            ledger = root / "network.jsonl"
            first = NetworkController("controller", ledger)
            first.register_remote("restored-worker", worker.capabilities(), InProcessTransport(worker))
            first.refresh_remote("restored-worker")
            identity = first.worker_state("restored-worker")["description_identity"]
            version = first.worker_state("restored-worker")["worker_service_version"]
            second = NetworkController("controller", ledger)
            second.register_remote("restored-worker", worker.capabilities(), InProcessTransport(worker))
            self.assertIsNone(second.worker_state("restored-worker")["description_identity"])
            restored = second.restore_last_known()
            self.assertEqual(restored["restored_workers"], 1)
            state = second.worker_state("restored-worker", apply_lease=False)
            self.assertEqual(state["description_identity"], identity)
            self.assertEqual(state["worker_service_version"], version)


class _ClassifiedRefreshBackend:
    def __init__(self) -> None:
        self.calls = 0
        self.last_deadline: float | None = None
        self.blocked_worker_ids: set[str] = set()
        self.registry_entries: dict[str, object] = {}

    def refresh_fleet(
        self,
        *,
        worker_ids: list[str] | None = None,
        operation_deadline: float | None = None,
        per_worker_deadline: float | None = None,
    ) -> dict[str, object]:
        del worker_ids, per_worker_deadline
        self.calls += 1
        self.last_deadline = operation_deadline
        time.sleep(0.05)
        return {
            "outcome": "PARTIAL",
            "observation_mode": "probed",
            "workers": [
                {
                    "worker_id": "fast-worker",
                    "availability": "AVAILABLE",
                    "refresh": "PASS",
                    "worker_service_version": "0.2.0a20",
                },
                {
                    "worker_id": "slow-worker",
                    "availability": "AVAILABLE",
                    "refresh": "TIMEOUT",
                    "deadline_fired": "worker",
                },
            ],
        }

    def workers(self, *, apply_lease: bool = True) -> list[dict[str, object]]:
        del apply_lease
        return [
            {
                "worker_id": "fast-worker",
                "availability": "AVAILABLE",
                "capability_inventory_status": "STALE",
                "capability_observation_fresh": False,
            },
            {
                "worker_id": "slow-worker",
                "availability": "AVAILABLE",
                "capability_inventory_status": "STALE",
                "capability_observation_fresh": False,
            },
        ]

    def close(self) -> None:
        return None


@unittest.skipUnless(os.name == "posix", "AF_UNIX persistent transport is currently POSIX-only")
class PersistentFleetRefreshDeadlineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = ControllerConfig(
            "controller-refresh-deadline",
            root / "lifecycle.jsonl",
            heartbeat_seconds=0.5,
            service_log=root / "controller-service.jsonl",
            socket_path=root / "controller.sock",
            admin_socket_path=root / "controller-admin.sock",
        )
        self.service = ControllerService(self.config)
        self.backend = _ClassifiedRefreshBackend()
        self.service._worker_client = self.backend
        self.thread = threading.Thread(
            target=self.service.run, kwargs={"max_seconds": 6.0}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 2.0
        while not self.config.socket_path_value.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.config.socket_path_value.exists())
        self.client = FabricClient.connect(
            self.config.socket_path_value,
            client_identity="refresh-deadline",
            timeout=0.4,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.service.request_stop()
        self.thread.join(timeout=3.0)
        self.temp.cleanup()

    def test_classified_refresh_returns_before_service_ttl_expires(self) -> None:
        started = time.monotonic()
        report = self.client.refresh_fleet()
        elapsed = time.monotonic() - started
        by_id = {item["worker_id"]: item for item in report["workers"]}
        self.assertEqual(report["outcome"], "PARTIAL")
        self.assertEqual(by_id["fast-worker"]["refresh"], "PASS")
        self.assertEqual(by_id["slow-worker"]["refresh"], "TIMEOUT")
        self.assertEqual(by_id["fast-worker"]["availability"], "AVAILABLE")
        self.assertIn(by_id["fast-worker"]["capability_inventory_status"], {"STALE", "UNKNOWN", "CURRENT"})
        self.assertNotEqual(by_id["fast-worker"]["capability_inventory_status"], "UNAVAILABLE")
        self.assertEqual(by_id["fast-worker"]["worker_service_version"], "0.2.0a20")
        self.assertLess(elapsed, 0.4)
        self.assertLess(self.backend.last_deadline or 99.0, SERVICE_REQUEST_TTL_SECONDS)
        self.assertGreater(self.backend.last_deadline or 0.0, 0.0)
        listed = self.client.workers()
        self.assertEqual(listed[0]["availability"], "AVAILABLE")
        self.assertNotEqual(listed[0]["capability_inventory_status"], "UNAVAILABLE")

    def test_status_reads_remain_last_known_during_and_after_partial_refresh(self) -> None:
        report = self.client.refresh_fleet()
        status = self.client.controller_status()
        self.assertEqual(report["outcome"], "PARTIAL")
        self.assertEqual(status["fleet"]["observation_mode"], "last-known")
        self.assertTrue(status["service_features"]["classified_fleet_refresh"])

    def test_short_client_ttl_still_receives_classified_result(self) -> None:
        transport = self.client._service_transport
        assert transport is not None
        payload = transport.request("fleet.refresh")
        by_id = {item["worker_id"]: item for item in payload["workers"]}
        self.assertEqual(payload["outcome"], "PARTIAL")
        self.assertEqual(by_id["fast-worker"]["refresh"], "PASS")
        self.assertLess(payload["operation_deadline_seconds"], 0.4)


class RemainingDeadlineTests(unittest.TestCase):
    def test_remaining_request_seconds_uses_expires_at(self) -> None:
        remaining = remaining_request_seconds(
            {
                "expires_at": "2099-01-01T00:00:01Z",
            },
            now=__import__("datetime").datetime(2099, 1, 1, tzinfo=__import__("datetime").timezone.utc),
        )
        self.assertAlmostEqual(remaining, 1.0, places=5)

    def test_operation_deadline_keeps_a_response_reserve_without_consuming_short_ttls(self) -> None:
        self.assertGreater(operation_deadline_seconds(30.0), 28.0)
        self.assertLess(operation_deadline_seconds(30.0), 30.0)
        self.assertGreater(operation_deadline_seconds(0.4), 0.2)
        self.assertLess(operation_deadline_seconds(0.4), 0.4)
        self.assertEqual(operation_deadline_seconds(0.0), 0.0)
