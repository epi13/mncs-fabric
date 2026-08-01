import unittest

from mncs_fabric.canonical import attach_identity
from mncs_fabric.reconcile import reconcile_records


def record(label: str, result="sha256:" + "a" * 64, outcome="PASS"):
    value = {
        "schema_version": "mncs-fabric.execution-record.v0.1",
        "job_identity": "sha256:" + "1" * 64,
        "candidate_identity": "sha256:" + "2" * 64,
        "evaluator_identity": None,
        "artifact_manifest_identity": "sha256:" + "3" * 64,
        "node": {"machine_label": label},
        "outcome": outcome,
        "results": [{"path": "result.json", "size": 2, "sha256": result}],
    }
    return attach_identity(value, "record_id")


class ReconcileTests(unittest.TestCase):
    def test_matching_records_pass(self):
        cohort = reconcile_records([record("a"), record("b")])
        self.assertEqual(cohort["outcome"], "PASS")
        self.assertEqual(cohort["evidence_class"], "OPERATOR_CONTROLLED_CROSS_HOST")

    def test_result_disagreement_fails(self):
        cohort = reconcile_records([record("a"), record("b", "sha256:" + "b" * 64)])
        self.assertEqual(cohort["outcome"], "FAIL")

    def test_unknown_dominates_pass(self):
        cohort = reconcile_records([record("a"), record("b", outcome="UNKNOWN")])
        self.assertEqual(cohort["outcome"], "UNKNOWN")

    def test_mutated_record_fails(self):
        bad = record("b")
        bad["outcome"] = "FAIL"
        cohort = reconcile_records([record("a"), bad])
        self.assertEqual(cohort["outcome"], "FAIL")
