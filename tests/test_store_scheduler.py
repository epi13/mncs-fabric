import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mncs_fabric.errors import StorageError
from mncs_fabric.scheduler import WorkerSlot, schedule
from mncs_fabric.store import FabricLedger


def identity(char: str) -> str:
    return "sha256:" + char * 64


def plan(capabilities=None):
    return {
        "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "scheduler:job", "candidate_identity": identity("a"), "evaluator_identity": None, "artifact_manifest_identity": identity("b"), "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": capabilities or ["python"], "result_paths": [], "network_policy": "UNSPECIFIED",
    }


class StoreTests(unittest.TestCase):
    def test_append_recovery_and_corruption_are_explicit(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "ledger.jsonl"
        ledger = FabricLedger(path)
        ledger.append("test", {"value": 1})
        ledger.append("test", {"value": 1})
        self.assertEqual(ledger.verify()["record_count"], 1)
        path.write_bytes(path.read_bytes().rstrip(b"\n"))
        self.assertEqual(ledger.recover()["diagnostics"][0]["code"], "TRAILING_NEWLINE_MISSING")
        self.assertTrue(ledger.recover(repair_truncated_tail=True)["repaired"])
        with path.open("ab") as stream:
            stream.write(b'{"interrupted":')
        with self.assertRaises(StorageError):
            ledger.records()
        diagnostic = ledger.recover()
        self.assertEqual(diagnostic["diagnostics"][0]["code"], "TRUNCATED_TAIL")
        repaired = ledger.recover(repair_truncated_tail=True)
        self.assertTrue(repaired["repaired"])
        self.assertEqual(ledger.verify()["record_count"], 1)

    def test_concurrent_append_and_future_schema_fail_closed(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "ledger.jsonl"
        ledger = FabricLedger(path)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda number: ledger.append("test", {"value": number}), range(20)))
        self.assertEqual(len(ledger.records(limit=100)), 20)
        lines = path.read_text(encoding="utf-8").splitlines()
        value = json.loads(lines[0])
        value["schema_version"] = "mncs-fabric.ledger.v99"
        path.write_text(json.dumps(value) + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
        with self.assertRaises(StorageError):
            ledger.verify()


class SchedulerTests(unittest.TestCase):
    def test_exact_match_tie_break_and_replication(self):
        workers = [WorkerSlot("b", frozenset({"python"})), WorkerSlot("a", frozenset({"python"}))]
        decision = schedule(plan(), workers, replicas=2)
        self.assertEqual(decision.worker_ids, ("a", "b"))

    def test_missing_capability_and_admission_exhaustion_are_explicit(self):
        missing = schedule(plan(["gpu"]), [WorkerSlot("a", frozenset({"python"}))])
        self.assertEqual(missing.disposition, "UNKNOWN")
        self.assertIn("CAPABILITY_UNAVAILABLE", missing.reason)
        exhausted = schedule(plan(), [WorkerSlot("a", frozenset({"python"}), active=1, concurrency_limit=1)])
        self.assertEqual(exhausted.disposition, "UNKNOWN")
        self.assertIn("ADMISSION_EXHAUSTED", exhausted.reason)
