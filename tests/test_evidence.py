from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from mncs_fabric.evidence import validate_two_host_evidence


class PhysicalEvidenceTests(unittest.TestCase):
    def test_sanitized_two_host_evidence_validates(self) -> None:
        evidence = json.loads((Path(__file__).parents[1] / "development-evidence/fedora-two-host-phase1.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_two_host_evidence(evidence)["outcome"], "PASS")

    def test_evidence_tampering_and_secret_material_fail_closed(self) -> None:
        evidence = json.loads((Path(__file__).parents[1] / "development-evidence/fedora-two-host-phase1.json").read_text(encoding="utf-8"))
        changed = copy.deepcopy(evidence)
        changed["worker_certificate_fingerprint"] = evidence["controller_certificate_fingerprint"]
        self.assertEqual(validate_two_host_evidence(changed)["outcome"], "FAIL")
        secret = copy.deepcopy(evidence)
        secret["private_key"] = "-----BEGIN PRIVATE KEY-----"
        self.assertEqual(validate_two_host_evidence(secret)["outcome"], "FAIL")
