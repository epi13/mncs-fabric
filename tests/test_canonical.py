import unittest

from mncs_fabric.canonical import attach_identity, canonical_json_bytes, verify_identity


class CanonicalTests(unittest.TestCase):
    def test_key_order_is_stable(self):
        self.assertEqual(canonical_json_bytes({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_identity_detects_mutation(self):
        record = attach_identity({"value": 1}, "record_id")
        self.assertTrue(verify_identity(record, "record_id"))
        record["value"] = 2
        self.assertFalse(verify_identity(record, "record_id"))
