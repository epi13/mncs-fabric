"""Stress and regression tests for bounded durable storage and RAM scaling.

These tests prove the fundamental invariant:
Fabric idle RAM is proportional primarily to active workers/jobs/runtime state,
not to the amount of historical work Fabric has ever processed.
"""

from __future__ import annotations

import gc
import json
import secrets
import tempfile
import time
import tracemalloc
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from mncs_fabric.canonical import attach_identity, canonical_json_bytes, sha256_identity
from mncs_fabric.controller_service import (
    ControllerConfig,
    ControllerService,
    SERVICE_REPLAY_MAX_ENTRIES,
    _ServiceReplayCache,
)
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.lifecycle import LifecycleStore
from mncs_fabric.worker_state import (
    validate_worker_description,
)
from mncs_fabric.node import collect_node_capabilities, utc_now
from mncs_fabric.rendezvous import RendezvousCoordinator
from mncs_fabric.resources import capture_resource_snapshot
from mncs_fabric.store import FabricLedger
from mncs_fabric.transport import TLSRendezvousWorker
from mncs_fabric.worker_state import build_worker_description


def _sample_worker_description(worker_id: str, *, sequence: int = 1) -> dict[str, Any]:
    node = collect_node_capabilities(worker_id)
    captured_at = (
        datetime.now(timezone.utc) + timedelta(microseconds=sequence)
    ).isoformat().replace("+00:00", "Z")
    return validate_worker_description(
        build_worker_description(
            worker_id=worker_id,
            node=node,
            resource_snapshot=capture_resource_snapshot(
                worker_id, node_fingerprint=node["node_fingerprint"]
            ),
            captured_at=captured_at,
        ),
        expected_worker_id=worker_id,
    )


class TestBoundedStorageArchitecture(unittest.TestCase):
    def test_rendezvous_worker_reuses_description_within_a_session(self) -> None:
        """Timestamped descriptions are sampled once, not once per heartbeat."""

        class ChangingWorker:
            def __init__(self) -> None:
                self.calls = 0

            def description(self) -> dict[str, Any]:
                self.calls += 1
                return _sample_worker_description("worker-1", sequence=self.calls)

        worker = ChangingWorker()
        client = TLSRendezvousWorker.__new__(TLSRendezvousWorker)
        client.worker = worker
        client._session_description = None

        first = client._description_payload()
        second = client._description_payload()

        self.assertEqual(worker.calls, 1)
        self.assertEqual(first["description"]["description_identity"], second["description"]["description_identity"])

    def test_ledger_does_not_retain_records_in_memory(self) -> None:
        """Ledger validation and reads must not grow instance RAM with ledger size."""
        with tempfile.TemporaryDirectory() as temp_dir:
            ledger_path = Path(temp_dir) / "large.jsonl"
            ledger = FabricLedger(ledger_path)

            # Append 2,000 records
            for i in range(2000):
                ledger.append("test.event", {"index": i, "data": "x" * 500})

            # Check stat token and record count are bounded metadata
            verify_res = ledger.verify()
            self.assertEqual(verify_res["outcome"], "PASS")
            self.assertEqual(verify_res["record_count"], 2000)

            # Re-instantiate ledger
            fresh_ledger = FabricLedger(ledger_path)

            gc.collect()
            tracemalloc.start()
            snap1 = tracemalloc.take_snapshot()

            # Verify large ledger
            fresh_ledger.verify()
            # Bounded read window
            recent = fresh_ledger.records(limit=10)
            self.assertEqual(len(recent), 10)

            gc.collect()
            snap2 = tracemalloc.take_snapshot()
            tracemalloc.stop()

            # The fresh ledger instance must only retain small bounded metadata
            # (token, sequence, diagnostics) — NOT all 2,000 decoded entries.
            self.assertEqual(len(fresh_ledger._diagnostics), 0)
            self.assertIsNotNone(fresh_ledger._verified_token)
            self.assertEqual(fresh_ledger._record_count, 2000)
            self.assertIsNotNone(fresh_ledger._last_entry)

    def test_rendezvous_heartbeats_do_not_bloat_durable_history(self) -> None:
        """Identical heartbeats must update live state in RAM without appending to JSONL."""
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "rendezvous.jsonl"
            coord = RendezvousCoordinator(
                controller_id="controller-1",
                state_path=state_path,
                heartbeat_seconds=5.0,
            )

            desc = _sample_worker_description("worker-1", sequence=1)
            opening = {
                "request_id": "req-1",
                "payload": {"description": desc},
            }
            accept = coord.open("worker-1", "sha256:" + "a" * 64, opening)
            session_id = accept["payload"]["session_id"]

            # Initial connection should be 1 record in ledger
            self.assertEqual(len(coord.ledger.all_records()), 1)

            # Send 500 identical heartbeats
            for i in range(500):
                hb_msg = {
                    "message_type": "worker.heartbeat",
                    "controller_id": "controller-1",
                    "worker_id": "worker-1",
                    "payload": {"description": desc},
                }
                ack = coord.message(session_id, hb_msg)
                self.assertEqual(ack["message_type"], "worker.heartbeat.ack")

            # Ledger record count MUST STILL BE 1 (connected), not 501!
            self.assertEqual(len(coord.ledger.all_records()), 1)

            # Timestamp-only drift (a fresh sample with no material change,
            # exactly what a per-beat worker report looks like) must also
            # record nothing: the old identity-based comparison re-created
            # the heartbeat flood in slower motion in production.
            drift = _sample_worker_description("worker-1", sequence=2)
            self.assertNotEqual(
                drift.get("description_identity"), desc.get("description_identity")
            )
            drift_msg = {
                "message_type": "worker.heartbeat",
                "controller_id": "controller-1",
                "worker_id": "worker-1",
                "payload": {"description": drift},
            }
            drift_ack = coord.message(session_id, drift_msg)
            self.assertEqual(drift_ack["message_type"], "worker.heartbeat.ack")
            self.assertEqual(len(coord.ledger.all_records()), 1)

            # Now update description (e.g. capabilities change)
            import copy

            from mncs_fabric.canonical import attach_identity as _attach

            desc2 = copy.deepcopy(drift)
            desc2["worker_service_version"] = "0.2.0a99"
            desc2.update(_attach(desc2, "description_identity"))
            hb_msg2 = {
                "message_type": "worker.heartbeat",
                "controller_id": "controller-1",
                "worker_id": "worker-1",
                "payload": {"description": desc2},
            }
            ack2 = coord.message(session_id, hb_msg2)
            self.assertEqual(ack2["message_type"], "worker.heartbeat.ack")

            # Ledger record count should now be 2 (connected + description_changed)
            records = coord.ledger.all_records()
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1]["record"]["event"], "description_changed")

            # Monotonic generation test: close and reopen session
            coord.close(session_id)
            self.assertEqual(len(coord.ledger.all_records()), 3)  # disconnected

            accept2 = coord.open("worker-1", "sha256:" + "a" * 64, opening)
            self.assertEqual(accept2["payload"]["generation"], 2)

    def test_service_replay_cache_bounded_and_fail_closed(self) -> None:
        """Service replay cache rejects duplicates within window and rejects expired requests."""
        cache = _ServiceReplayCache()
        now = datetime.now(timezone.utc)

        future_iso = (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
        past_iso = (now - timedelta(seconds=60)).isoformat().replace("+00:00", "Z")

        # First request succeeds
        cache.check_and_record("req-1", future_iso)
        self.assertEqual(cache.count, 1)

        # Replay within expiration window raises ProtocolError
        with self.assertRaises(ProtocolError):
            cache.check_and_record("req-1", future_iso)

        # Distinct request succeeds
        cache.check_and_record("req-2", future_iso)
        self.assertEqual(cache.count, 2)

        # Invalid timestamp raises ValidationError
        with self.assertRaises(ValidationError):
            cache.check_and_record("req-3", "not-a-timestamp")

        # Expired requests never enter the replay state.
        with self.assertRaises(ValidationError):
            cache.check_and_record("req-expired", past_iso)

        # Restart-safe state preserves replay protection, while the cache has
        # a hard upper bound even when fed distinct request identities.
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "replay.json"
            persisted = _ServiceReplayCache(state_path)
            persisted.check_and_record("persisted", future_iso)
            restored = _ServiceReplayCache(state_path)
            with self.assertRaises(ProtocolError):
                restored.check_and_record("persisted", future_iso)

        bounded = _ServiceReplayCache()
        for index in range(SERVICE_REPLAY_MAX_ENTRIES):
            bounded.check_and_record(f"bounded-{index}", future_iso)
        self.assertEqual(bounded.count, SERVICE_REPLAY_MAX_ENTRIES)
        with self.assertRaises(ProtocolError):
            bounded.check_and_record("bounded-overflow", future_iso)

    def test_detached_execution_result_externalization_and_backward_compatibility(self) -> None:
        """Large results are stored on disk while ledger keeps compact reference; legacy inline results read seamlessly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = ControllerConfig(
                controller_id="ctrl-1",
                lifecycle_state=root / "lifecycle.jsonl",
                service_log=root / "controller-service.jsonl",
            )
            svc = ControllerService(config)

            # Create large result (500 KB)
            large_result = {
                "schema_version": "mncs-fabric.consumer-result.v0.1",
                "disposition": "PASS",
                "worker_identity": "worker-1",
                "blob": "y" * (500 * 1024),
            }
            work_id = "a" * 64

            # Append completed event
            svc._append_detached_event(
                work_id,
                "COMPLETED",
                attempt=1,
                result=large_result,
            )

            # Verify ledger entry does not hold large result inline
            records = svc.detached_ledger.all_records()
            self.assertEqual(len(records), 1)
            event_rec = records[0]["record"]
            self.assertIsNone(event_rec["result"])
            self.assertIsNotNone(event_rec["result_identity"])

            # Verify file exists on disk
            result_identity = event_rec["result_identity"]
            result_file = root / "detached-results" / f"{result_identity[7:]}.json"
            self.assertTrue(result_file.exists())

            # Load via _get_detached_result
            loaded = svc._get_detached_result(work_id)
            self.assertEqual(loaded["blob"], "y" * (500 * 1024))

            # Backward compatibility: Legacy ledger with inline result
            legacy_work_id = "b" * 64
            legacy_result = {"legacy": True, "value": 42}
            legacy_event = {
                "schema_version": "mncs-fabric.detached-execution.v0.1",
                "work_id": legacy_work_id,
                "state": "COMPLETED",
                "attempt": 1,
                "observed_at": utc_now(),
                "reason": None,
                "result": legacy_result,
            }
            svc.detached_ledger.append(
                "detached.execution",
                {"schema_version": "mncs-fabric.detached-execution.v0.1", **legacy_event, "event_identity": sha256_identity(legacy_event)},
            )

            # Invalidate index token to pick up raw ledger append
            svc._detached_index_token = None

            # Read legacy result via _get_detached_result
            legacy_loaded = svc._get_detached_result(legacy_work_id)
            self.assertEqual(legacy_loaded, legacy_result)

    def test_storage_diagnostics_in_status_and_doctor(self) -> None:
        """Controller service status and doctor report bounded storage metadata."""
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = ControllerConfig(
                controller_id="ctrl-1",
                lifecycle_state=root / "lifecycle.jsonl",
                service_log=root / "controller-service.jsonl",
            )
            svc = ControllerService(config)

            status = svc.status()
            self.assertIn("storage", status)
            storage = status["storage"]
            self.assertIn("service_ledger", storage)
            self.assertIn("lifecycle_ledger", storage)
            self.assertIn("detached_ledger", storage)
            self.assertIn("projections", storage)
            projections = storage["projections"]
            self.assertIn("replay_cache_size", projections)
            self.assertIn("detached_jobs", projections)

            doc = svc.doctor()
            self.assertEqual(doc["checks"]["storage"], "PASS")

    def test_ledger_append_scales_constantly_and_detects_duplicates_and_corruption(self) -> None:
        """Append latency does not scale linearly with ledger history while preserving duplicate/collision/corruption guarantees."""
        from mncs_fabric.errors import StorageError

        with tempfile.TemporaryDirectory() as temp_dir:
            ledger_path = Path(temp_dir) / "scaling.jsonl"
            ledger = FabricLedger(ledger_path)

            # Seed 200 initial records and measure per-append time
            for i in range(200):
                ledger.append("event.alpha", {"seq": i, "payload": "a" * 256})
            t_small_0 = time.perf_counter()
            for i in range(200, 220):
                ledger.append("event.alpha", {"seq": i, "payload": "a" * 256})
            small_per_append = (time.perf_counter() - t_small_0) / 20.0

            # Grow to 4,000 records (20x larger) and measure per-append time
            for i in range(220, 4000):
                ledger.append("event.beta" if i % 5 == 0 else "event.alpha", {"seq": i, "payload": "a" * 256})
            t_large_0 = time.perf_counter()
            for i in range(4000, 4020):
                ledger.append("event.alpha", {"seq": i, "payload": "a" * 256})
            large_per_append = (time.perf_counter() - t_large_0) / 20.0

            # Reopened instance append on 4,020-record ledger
            reopened = FabricLedger(ledger_path)
            t_reopen_0 = time.perf_counter()
            reopened.append("event.beta", {"seq": 4020, "payload": "a" * 256})
            reopen_append = time.perf_counter() - t_reopen_0

            # Large append and reopened append must remain fast (< 25ms per append)
            self.assertLess(small_per_append, 0.025)
            self.assertLess(large_per_append, 0.025)
            self.assertLess(reopen_append, 0.050)

            # Duplicate idempotent return & conflicting record_type rejection at head, middle, and tail
            for target_seq in (0, 2000, 4020):
                expected_type = "event.beta" if (target_seq == 4020 or (target_seq >= 220 and target_seq % 5 == 0)) else "event.alpha"
                dup = reopened.append(expected_type, {"seq": target_seq, "payload": "a" * 256})
                self.assertEqual(dup["sequence"], target_seq + 1)
                with self.assertRaisesRegex(StorageError, "conflicting duplicate record identity"):
                    reopened.append("event.conflicting", {"seq": target_seq, "payload": "a" * 256})

            # Indexed filtered tail window query
            beta_tail = reopened.records(record_type="event.beta", limit=3)
            self.assertEqual([e["record"]["seq"] for e in beta_tail], [3990, 3995, 4020])

            # Corrupting or deleting the sidecar .idx file auto-recovers transparently
            idx_path = ledger_path.with_name(ledger_path.name + ".idx")
            self.assertTrue(idx_path.exists())
            idx_path.write_bytes(b"corrupted-sqlite-header")
            recovered_reader = FabricLedger(ledger_path)
            self.assertEqual(recovered_reader.records(record_type="event.beta", limit=1)[0]["record"]["seq"], 4020)
            recovered_reader.append("event.alpha", {"seq": 4021, "payload": "a" * 256})
            self.assertEqual(recovered_reader.verify()["record_count"], 4022)

            # Corrupting an interior ledger record in .jsonl is caught by verify() and all_records()
            lines = ledger_path.read_text(encoding="utf-8").splitlines()
            mid = json.loads(lines[1500])
            mid["record"]["payload"] = "tampered"
            lines[1500] = json.dumps(mid, sort_keys=True)
            ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            auditor = FabricLedger(ledger_path)
            with self.assertRaises(StorageError):
                auditor.verify()
            with self.assertRaises(StorageError):
                auditor.all_records()

    def test_network_controller_suppresses_unchanged_liveness_and_telemetry_drift(self) -> None:
        """Repeated fleet refreshes with unchanged unavailability or volatile description drift do not bloat the ledger."""
        import copy
        from mncs_fabric.controller import NetworkController
        from tests.test_fleet_refresh import _CachedDescribeTransport, _DownTransport

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ledger_path = root / "controller-workers-network.jsonl"
            ctrl = NetworkController("ctrl-1", ledger_path)
            desc1 = _sample_worker_description("worker-up", sequence=1)
            up_transport = _CachedDescribeTransport(desc1)
            ctrl.register_remote("worker-up", frozenset({"python"}), up_transport)
            ctrl.register_remote("worker-down", frozenset({"python"}), _DownTransport())

            # First fleet refresh records initial worker.description.request, worker.description, worker.state, and down worker.liveness
            report1 = ctrl.refresh_fleet()
            self.assertEqual(report1["outcome"], "PASS")
            initial_count = len(ctrl.ledger.all_records())
            self.assertEqual(initial_count, 4)

            # 20 repeated refreshes with volatile timestamp/telemetry drift on worker-up and same failure on worker-down
            for seq in range(2, 22):
                up_transport.description = _sample_worker_description("worker-up", sequence=seq)
                ctrl.refresh_fleet()

            # Ledger record count must remain 4 (no bloat from unchanged unavailability or timestamp drift)
            self.assertEqual(len(ctrl.ledger.all_records()), initial_count)

            # Material change on worker-up (service version change) IS persisted
            material_desc = copy.deepcopy(up_transport.description)
            material_desc["worker_service_version"] = "0.2.0a99"
            material_desc.update(attach_identity(material_desc, "description_identity"))
            up_transport.description = material_desc
            ctrl.refresh_fleet()
            self.assertEqual(len(ctrl.ledger.all_records()), initial_count + 3)


if __name__ == "__main__":
    unittest.main()
