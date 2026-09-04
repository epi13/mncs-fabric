"""Ledger compaction: drop superseded heartbeats, reseal the chain, stay bounded.

Regression coverage for the production incident where a worker-initiated
rendezvous controller retained a heartbeat record (with a full embedded
worker description) on every beat. The ledger grew past 1 GB / ~200k
entries and resident reader caches grew with it into multi-gigabyte RSS.
"""

from __future__ import annotations

import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from mncs_fabric.canonical import attach_identity
from mncs_fabric.errors import StorageError
from mncs_fabric.rendezvous import (
    RendezvousCoordinator,
    compact_superseded_heartbeats,
)
from mncs_fabric.store import FabricLedger


def _record(event: str, worker: str, session: str, generation: int, seq_note: int = 0) -> dict:
    return attach_identity(
        {
            "schema_version": "mncs-fabric.worker-rendezvous.v0.1",
            "event": event,
            "worker_id": worker,
            "session_id": session,
            "generation": generation,
            "certificate_fingerprint": "sha256:" + "ab" * 32,
            "observed_at": f"2026-09-04T00:00:{seq_note:02d}Z",
            "description": {"worker_identity": worker, "note": f"description-{seq_note}"},
        },
        "rendezvous_event_id",
    )


def _build_ledger(path: Path, *, sessions: int = 2, heartbeats: int = 50) -> FabricLedger:
    ledger = FabricLedger(path)
    for session_index in range(sessions):
        session = f"session-{session_index}"
        generation = session_index + 1
        ledger.append("worker.rendezvous", _record("connected", "worker-03", session, generation))
        for beat in range(heartbeats):
            ledger.append(
                "worker.rendezvous",
                _record("heartbeat", "worker-03", session, generation, seq_note=beat % 60),
            )
        ledger.append(
            "worker.rendezvous", _record("disconnected", "worker-03", session, generation)
        )
    return ledger


class TestLedgerCompaction(unittest.TestCase):
    def test_drops_only_superseded_heartbeats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            _build_ledger(path, sessions=2, heartbeats=50)
            coordinator = RendezvousCoordinator("test-controller", path)
            report = compact_superseded_heartbeats(
                coordinator, reason="test: superseded heartbeat compaction"
            )
            self.assertEqual(report["pre_compact_count"], 2 * 52)
            self.assertEqual(report["kept_count"], 2 * 3)  # connected + latest beat + disconnected
            self.assertEqual(report["dropped_count"], 2 * 49)
            self.assertEqual(report["post_compact_count"], 2 * 3 + 1)  # plus receipt

    def test_compacted_ledger_verifies_and_preserves_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            ledger = _build_ledger(path, sessions=1, heartbeats=10)
            before = {
                entry["record_identity"]: entry["record"]
                for entry in ledger.all_records()
                if entry["record"].get("event") != "heartbeat"
            }
            coordinator = RendezvousCoordinator("test-controller", path)
            compact_superseded_heartbeats(coordinator, reason="test: verify after compact")
            fresh = FabricLedger(path)
            verification = fresh.verify()
            self.assertEqual(verification["outcome"], "PASS")
            after = {
                entry["record_identity"]: entry["record"] for entry in fresh.all_records()
            }
            for identity, record in before.items():
                self.assertIn(identity, after)
                self.assertEqual(after[identity], record)
            receipts = fresh.all_records(record_type="ledger.compaction")
            self.assertEqual(len(receipts), 1)
            receipt = receipts[0]["record"]
            self.assertEqual(receipt["dropped_count"], 9)
            self.assertTrue(receipt["pre_compact_head"].startswith("sha256:"))
            sequences = [entry["sequence"] for entry in fresh.all_records()]
            self.assertEqual(sequences, sorted(sequences))
            self.assertEqual(sequences, list(range(1, len(sequences) + 1)))

    def test_generation_maximum_survives_compaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            coordinator = RendezvousCoordinator("test-controller", path)
            ledger = coordinator.ledger
            ledger.append("worker.rendezvous", _record("connected", "w1", "s1", 7))
            for beat in range(5):
                ledger.append("worker.rendezvous", _record("heartbeat", "w1", "s1", 7))
            before = coordinator._generation("w1")
            compact_superseded_heartbeats(coordinator, reason="test: generation survival")
            self.assertEqual(before, 7)
            self.assertEqual(coordinator._generation("w1"), 7)

    def test_compaction_arguments_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            ledger = _build_ledger(path, sessions=1, heartbeats=3)
            with self.assertRaises(StorageError):
                ledger.compact(keep=lambda entry: True, reason="")
            with self.assertRaises(StorageError):
                ledger.compact(keep=lambda entry: True, reason="ok", max_kept=0)
            with self.assertRaises(StorageError):
                ledger.compact(keep=None, reason="ok")  # type: ignore[arg-type]
            # The failed compactions must not have rewritten history.
            self.assertEqual(ledger.verify()["record_count"], 5)

    def test_kept_bound_trips_before_unbounded_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            ledger = _build_ledger(path, sessions=1, heartbeats=10)
            with self.assertRaises(StorageError):
                ledger.compact(keep=lambda entry: True, reason="ok", max_kept=5)
            self.assertEqual(ledger.verify()["record_count"], 12)

    def test_no_full_retention_cache_on_production_ledger(self) -> None:
        # Structural guard: the installed build that reached ~3 GB RSS kept
        # every ledger record in a resident list. That shape must not return.
        ledger = FabricLedger(Path("/nonexistent-probe-only.jsonl"))
        for attribute in ("_read_cache_records", "_read_cache_token", "_record_cache"):
            self.assertFalse(
                hasattr(ledger, attribute), f"FabricLedger must not retain {attribute}"
            )

    def test_compact_and_verify_stay_memory_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            ledger = FabricLedger(path)
            big_description = {"worker_identity": "worker-03", "blob": "x" * 2048}
            for beat in range(3000):
                ledger.append(
                    "worker.rendezvous",
                    attach_identity(
                        {
                            "schema_version": "mncs-fabric.worker-rendezvous.v0.1",
                            "event": "heartbeat",
                            "worker_id": "worker-03",
                            "session_id": "session-0",
                            "generation": 1,
                            "certificate_fingerprint": "sha256:" + "ab" * 32,
                            "observed_at": "2026-09-04T00:00:00Z",
                            "description": big_description,
                        },
                        "rendezvous_event_id",
                    ),
                )
            ledger.append(
                "worker.rendezvous", _record("connected", "worker-03", "session-0", 1)
            )
            coordinator = RendezvousCoordinator("test-controller", path)
            tracemalloc.start()
            try:
                compact_superseded_heartbeats(coordinator, reason="test: memory bound")
                current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            # 3000 fat records (~7 MB on disk) must compact in a small
            # fraction of that: streaming, not retained history.
            self.assertLess(peak, 30 * 1024 * 1024, f"peak traced bytes: {peak}")
            self.assertEqual(coordinator.ledger.verify()["outcome"], "PASS")


class TestLedgerCli(unittest.TestCase):
    def test_compact_and_verify_commands(self) -> None:
        from mncs_fabric import cli

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            _build_ledger(path, sessions=1, heartbeats=20)
            before = path.stat().st_size
            self.assertEqual(cli.main(["ledger", "verify", str(path)]), 0)
            self.assertEqual(
                cli.main(
                    [
                        "ledger",
                        "compact",
                        str(path),
                        "--policy",
                        "rendezvous-heartbeats",
                        "--reason",
                        "test: cli compaction",
                    ]
                ),
                0,
            )
            self.assertLess(path.stat().st_size, before)
            self.assertEqual(cli.main(["ledger", "verify", str(path)]), 0)

    def test_dry_run_leaves_history_untouched(self) -> None:
        from mncs_fabric import cli

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rendezvous.jsonl"
            _build_ledger(path, sessions=1, heartbeats=20)
            digest_before = path.read_bytes()
            self.assertEqual(
                cli.main(
                    [
                        "ledger",
                        "compact",
                        str(path),
                        "--policy",
                        "rendezvous-heartbeats",
                        "--reason",
                        "test: dry run",
                        "--dry-run",
                    ]
                ),
                0,
            )
            self.assertEqual(path.read_bytes(), digest_before)


if __name__ == "__main__":
    unittest.main()
