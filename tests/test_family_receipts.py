import copy
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.canonical import sha256_identity
from mncs_fabric.receipts import (
    build_execution_assurance,
    build_execution_receipt,
    build_family_execution_reference,
)
from mncs_fabric.executor import execute_local


def identity(char: str) -> str:
    return "sha256:" + char * 64


class ReceiptTests(unittest.TestCase):
    def _record(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('ok')\n", encoding="utf-8")
        manifest = build_manifest(root)
        plan = {
            "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "receipt:job",
            "candidate_identity": identity("a"), "evaluator_identity": None,
            "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"],
            "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096,
            "environment": {"PYTHONHASHSEED": "0"}, "required_capabilities": ["python"],
            "result_paths": ["result.json"], "network_policy": "DECLARED_OFFLINE",
        }
        return execute_local(plan, root, manifest, "receipt-node")

    def test_receipt_is_deterministic_and_preserves_claim_boundary(self):
        record = self._record()
        first = build_execution_receipt(record)
        second = build_execution_receipt(record)
        self.assertEqual(first, second)
        self.assertEqual(len(first["receipt_identity"]), 64)
        self.assertTrue(all(char in "0123456789abcdef" for char in first["receipt_identity"]))
        self.assertEqual(first["claim_boundary"]["conformance"], "not-asserted")
        self.assertEqual(first["enforcement"]["filesystem_restriction"], "unknown")
        self.assertIsNone(first["placement"]["execution_placement_reference"])

    def test_substitution_changes_identity_and_assurance_stays_unknown(self):
        record = self._record()
        first = build_execution_receipt(record)
        for field, replacement in (("candidate_identity", identity("b")), ("artifact_manifest_identity", identity("c")), ("resolved_executable_identity", identity("d"))):
            substituted = copy.deepcopy(record)
            substituted[field] = replacement
            self.assertNotEqual(first["receipt_identity"], build_execution_receipt(substituted)["receipt_identity"])
        substituted = copy.deepcopy(record)
        substituted["node"] = copy.deepcopy(record["node"])
        substituted["node"]["node_fingerprint"] = identity("e")
        self.assertNotEqual(first["receipt_identity"], build_execution_receipt(substituted)["receipt_identity"])
        second = build_execution_receipt(copy.deepcopy(record))
        self.assertEqual(first["receipt_identity"], second["receipt_identity"])
        assurance = build_execution_assurance(first)
        self.assertEqual(assurance["declared_assurance_status"], "UNKNOWN")
        self.assertEqual(assurance["execution"]["properties"]["network_isolation"], "UNKNOWN")

    def test_family_reference_preserves_attempt_and_execution_authority_boundary(self):
        record = self._record()
        receipt = build_execution_receipt(record)
        reference = build_family_execution_reference(
            record,
            receipt=receipt,
            attempt=2,
            retry_of="mncs-fabric://execution/prior/attempt/1",
            backend_identity="mncs:language:backend:reference-interpreter",
        )
        self.assertTrue(reference["stable_id"].endswith("/attempt/2"))
        self.assertEqual(reference["source_outcome"], record["outcome"])
        self.assertEqual(reference["receipt_identity"], receipt["receipt_identity"])
        self.assertNotIn("experiment_status", reference)
        self.assertIn("not Concept Experiment success", reference["claim_boundary"])

    def test_family_reference_rejects_invalid_attempt(self):
        with self.assertRaises(ValueError):
            build_family_execution_reference(self._record(), attempt=0)
