"""Rights & Provenance evidence emission tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.provenance import (
    EVIDENCE_SCHEMA_VERSION,
    build_provenance_evidence,
    compute_content_digest,
    verify_provenance_evidence,
)


def sample_record() -> dict:
    return {
        "schema_version": "mncs-fabric.execution-record.v0.1",
        "record_id": "fabric-record-0001",
        "job_id": "job-42",
        "job_identity": "sha256:" + "a" * 64,
        "candidate_identity": "candidate-7",
        "node": {"node_fingerprint": "fp-" + "b" * 32, "machine_label": "worker-01"},
        "started_at": "2026-08-24T10:00:00+00:00",
        "finished_at": "2026-08-24T10:00:02+00:00",
        "duration_ms": 2000,
        "declared_argv": ["/usr/bin/python3", "-m", "evaluator"],
        "outcome": "PASS",
        "termination_reason": None,
        "exit_code": 0,
        "results": [
            {"path": "out/solution.json", "size_bytes": 128, "sha256": "c" * 64},
            {"path": "out/log.txt", "size_bytes": 4096, "sha256": "d" * 64},
        ],
    }


class BuildProvenanceEvidenceTests(unittest.TestCase):
    def test_basic_projection_shape(self) -> None:
        evidence = build_provenance_evidence(sample_record())
        self.assertEqual(evidence["schema_version"], EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(evidence["kind"], "fabric-execution")
        self.assertEqual(
            evidence["evidence_id"],
            "mncs-fabric://execution/fabric-record-0001/rights-evidence",
        )
        output_refs = [
            ref for ref in evidence["subject"]["artifact_refs"] if ref["role"] == "output"
        ]
        self.assertEqual(len(output_refs), 2)
        self.assertEqual(output_refs[0]["hash_value"], "c" * 64)

    def test_content_digest_is_deterministic_and_tamper_detecting(self) -> None:
        first = build_provenance_evidence(sample_record())
        second = build_provenance_evidence(sample_record())
        # Timestamps come from the record; digests must be identical.
        self.assertEqual(first["content_digest"], second["content_digest"])
        ok, expected = verify_provenance_evidence(first)
        self.assertTrue(ok)
        tampered = dict(first)
        tampered["claims"] = [{"claim_type": "other", "statement": "changed"}]
        broken, _ = verify_provenance_evidence(tampered)
        self.assertFalse(broken)
        self.assertEqual(expected, first["content_digest"])
        self.assertNotEqual(compute_content_digest(tampered), first["content_digest"])

    def test_fabric_never_classifies_origin_by_itself(self) -> None:
        evidence = build_provenance_evidence(sample_record())
        claims = evidence["claims"]
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["confidence"], "insufficient-evidence")
        self.assertIn("No origin classification asserted by Fabric", claims[0]["statement"])

    def test_caller_origin_proposal_is_carried_as_claim_not_fact(self) -> None:
        evidence = build_provenance_evidence(
            sample_record(),
            origin_proposal={"classification": "autonomous-machine-generated", "confidence": "low"},
        )
        claim = evidence["claims"][0]
        self.assertEqual(claim["claim_type"], "origin-classification-proposal")
        self.assertEqual(claim["value"], "autonomous-machine-generated")
        self.assertEqual(claim["confidence"], "low")

    def test_rejects_unknown_origin_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            del tmp
            with self.assertRaises(ValueError):
                build_provenance_evidence(
                    sample_record(),
                    origin_proposal={"classification": "definitely-copyrightable", "confidence": "high"},
                )

    def test_receipt_reference_included_when_present(self) -> None:
        receipt = {
            "schema_version": "0.1-experimental",
            "record_type": "mncs-execution-receipt",
            "receipt_identity": "e" * 64,
        }
        evidence = build_provenance_evidence(sample_record(), receipt=receipt)
        receipt_refs = [
            ref for ref in evidence["references"] if ref["kind"] == "fabric-receipt"
        ]
        self.assertEqual(len(receipt_refs), 1)
        self.assertEqual(receipt_refs[0]["reference"], "sha256:" + "e" * 64)

    def test_oversized_argv_referenced_by_digest_only(self) -> None:
        record = sample_record()
        record["declared_argv"] = ["x" * 10000]
        evidence = build_provenance_evidence(record)
        argv_observations = [
            item for item in evidence["observations"] if item["name"] == "declared_argv_digest"
        ]
        self.assertEqual(len(argv_observations), 1)
        self.assertNotIn("value", argv_observations[0])
        self.assertTrue(argv_observations[0]["value_digest"].startswith("sha256:"))

    def test_requires_record_id(self) -> None:
        with self.assertRaises(ValueError):
            build_provenance_evidence({"schema_version": "mncs-fabric.execution-record.v0.1"})


if __name__ == "__main__":
    unittest.main()
