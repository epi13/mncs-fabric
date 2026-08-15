from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.management import (
    ManagementStore,
    build_management_state,
    can_transition,
    management_allows_work,
    transition_management_state,
)
from mncs_fabric.scheduler import WorkerSlot, schedule
from mncs_fabric.models import validate_job_plan
from mncs_fabric.canonical import sha256_identity


def _plan() -> dict:
    digest = sha256_identity({"job": "management"})
    return validate_job_plan({
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "management:job",
        "candidate_identity": digest,
        "evaluator_identity": None,
        "artifact_manifest_identity": digest,
        "argv": ["@python", "task.py"],
        "working_directory": ".",
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
        "environment": {},
        "required_capabilities": ["python"],
        "result_paths": [],
        "network_policy": "UNSPECIFIED",
    })


class ManagementStateTests(unittest.TestCase):
    def test_failed_certification_cannot_be_ready(self) -> None:
        with self.assertRaises(ValidationError):
            build_management_state(worker_id="w", state="READY", reason="no", certification_status="FAILED")

    def test_transition_table_and_work_gate(self) -> None:
        self.assertTrue(can_transition("READY", "DRAINING"))
        self.assertTrue(can_transition("READY", "MAINTENANCE"))
        self.assertTrue(can_transition("DRAINING", "MAINTENANCE"))
        self.assertTrue(can_transition("VERIFYING", "READY"))
        self.assertFalse(can_transition("QUARANTINED", "READY"))
        self.assertTrue(management_allows_work("READY"))
        self.assertFalse(management_allows_work("MAINTENANCE"))
        self.assertFalse(management_allows_work("QUARANTINED"))

    def test_store_persists_and_rejects_illegal_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ManagementStore(Path(directory) / "mgmt.jsonl")
            created = store.ensure("w1")
            self.assertEqual(created["state"], "READY")
            drained = store.set_state("w1", state="DRAINING", reason="drain")
            self.assertEqual(drained["state"], "DRAINING")
            store.set_state("w1", state="MAINTENANCE", reason="idle")
            store.set_state("w1", state="VERIFYING", reason="applied")
            failed = store.set_state("w1", state="QUARANTINED", reason="cert failed", certification_status="FAILED")
            self.assertEqual(failed["certification_status"], "FAILED")
            with self.assertRaises(ProtocolError):
                store.set_state("w1", state="READY", reason="nope")

    def test_scheduler_skips_maintenance_workers(self) -> None:
        ready = WorkerSlot(worker_id="ready", capabilities=frozenset({"python"}), management_state="READY")
        down = WorkerSlot(worker_id="maint", capabilities=frozenset({"python"}), management_state="MAINTENANCE")
        decision = schedule(_plan(), [down, ready])
        self.assertEqual(decision.disposition, "PASS")
        self.assertEqual(decision.worker_ids, ("ready",))
        blocked = schedule(_plan(), [down])
        self.assertEqual(blocked.disposition, "UNKNOWN")
