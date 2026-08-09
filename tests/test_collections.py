from __future__ import annotations

import unittest

from mncs_fabric.collections import build_execution_collection, build_work_item, validate_execution_collection
from mncs_fabric.errors import ValidationError


class ExecutionCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.items = [
            build_work_item(job_identity="sha256:" + "a" * 64, partition_identity="sha256:" + "b" * 64),
            build_work_item(job_identity="sha256:" + "c" * 64, partition_identity="sha256:" + "d" * 64),
        ]

    def test_complete_collection_is_identity_addressable(self) -> None:
        results = [
            {"work_item_identity": self.items[0]["work_item_identity"], "disposition": "PASS", "worker_identity": "worker-a", "record_identity": "sha256:" + "1" * 64},
            {"work_item_identity": self.items[1]["work_item_identity"], "disposition": "PASS", "worker_identity": "worker-b", "record_identity": "sha256:" + "2" * 64},
        ]
        collection = build_execution_collection(self.items, results)
        self.assertEqual(collection["outcome"], "PASS")
        self.assertEqual(validate_execution_collection(collection), collection)

    def test_missing_work_item_is_unknown(self) -> None:
        collection = build_execution_collection(self.items, [{"work_item_identity": self.items[0]["work_item_identity"], "disposition": "PASS", "record_identity": "sha256:" + "1" * 64}])
        self.assertEqual(collection["outcome"], "UNKNOWN")
        self.assertIn("MISSING", {entry["disposition"] for entry in collection["entries"]})

    def test_exact_duplicate_is_classified_but_does_not_erase_completion(self) -> None:
        result = {"work_item_identity": self.items[0]["work_item_identity"], "disposition": "PASS", "record_identity": "sha256:" + "1" * 64}
        collection = build_execution_collection([self.items[0]], [result, dict(result)])
        self.assertEqual(collection["outcome"], "PASS")
        self.assertIn("DUPLICATE_IDEMPOTENT", {entry["disposition"] for entry in collection["entries"]})

    def test_conflicting_duplicate_fails_closed(self) -> None:
        item = self.items[0]
        collection = build_execution_collection([item], [
            {"work_item_identity": item["work_item_identity"], "disposition": "PASS", "record_identity": "sha256:" + "1" * 64},
            {"work_item_identity": item["work_item_identity"], "disposition": "PASS", "record_identity": "sha256:" + "2" * 64},
        ])
        self.assertEqual(collection["outcome"], "FAIL")

    def test_undeclared_result_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            build_execution_collection([self.items[0]], [{"work_item_identity": "sha256:" + "f" * 64, "disposition": "PASS", "record_identity": "sha256:" + "1" * 64}])
