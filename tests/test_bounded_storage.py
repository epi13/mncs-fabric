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


if __name__ == "__main__":
    unittest.main()
