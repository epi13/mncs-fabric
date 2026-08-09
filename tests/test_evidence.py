from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from mncs_fabric.evidence import validate_native_bundle_two_host_evidence, validate_persistent_two_host_evidence, validate_two_host_evidence


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

    def test_persistent_two_host_evidence_validates(self) -> None:
        evidence = json.loads((Path(__file__).parents[1] / "development-evidence/fedora-persistent-two-host.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_persistent_two_host_evidence(evidence)["outcome"], "PASS")

    def test_native_bundle_evidence_rejects_transport_or_claim_substitution(self) -> None:
        evidence = {
            "schema_version": "mncs-fabric.native-bundle-two-host.v0.1",
            "record_type": "mncs-fabric.native-bundle-two-host",
            "fabric_commit": "a" * 40,
            "worker_fabric_commit": "a" * 40,
            "direct_fabric_tls": True,
            "ssh_tunnel_used": False,
            "ssh_staged_candidate_material": False,
            "controller_identity": "controller",
            "worker_identity": "worker",
            "bundle": {"logical_identity": "b" * 64, "archive_identity": "sha256:" + "c" * 64, "transfer_status": "COMMITTED"},
            "consumer_context": {"schema_version": "mncs-fabric.consumer-context.v0.1", "source_project": "MNEL", "consumer_workload_identity": "sha256:" + "1" * 64, "experiment_identity": None, "forge_workflow_identity": None, "provider_identity": None, "partition_identity": None, "authority": "provenance-only", "claim_boundary": "opaque consumer provenance; no semantic verdict, promotion, conformance, or evaluator authority", "context_identity": "sha256:" + "0" * 64},
            "requests": [{"disposition": "EXECUTED"}, {"disposition": "EXECUTED"}, {"disposition": "DUPLICATE_IDEMPOTENT"}, {"disposition": "CONFLICTING_REPLAY"}],
            "local_record_identity": "sha256:" + "d" * 64,
            "remote_record_identity": "sha256:" + "e" * 64,
            "reconciliation": {"outcome": "PASS"},
            "adversarial": {"revoked_controller": {"disposition": "FAIL_CLOSED"}, "challenge_replay": True},
            "claim_boundary": "no semantic verdict; no sandbox, correctness, custody, independence, conformance, or certification claim",
            "limitations": ["operator-controlled"],
        }
        self.assertEqual(validate_native_bundle_two_host_evidence(evidence)["outcome"], "FAIL")
