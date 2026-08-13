from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from mncs_fabric.evidence import validate_native_bundle_two_host_evidence, validate_persistent_two_host_evidence, validate_physical_evidence, validate_two_host_evidence


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

    def test_worker_state_evidence_validates_description_collection_and_loss(self) -> None:
        evidence = json.loads((Path(__file__).parents[1] / "development-evidence/fedora-worker-state.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_physical_evidence(evidence)["outcome"], "PASS")
        tampered = copy.deepcopy(evidence)
        tampered["worker_description"]["worker_identity"] = "substituted-worker"
        self.assertEqual(validate_physical_evidence(tampered)["outcome"], "FAIL")

    def test_fedora_reboot_unknown_is_preserved_and_pass_requires_identity_bindings(self) -> None:
        root = Path(__file__).parents[1] / "development-evidence"
        unknown = json.loads((root / "fedora-reboot-acceptance-unknown.json").read_text(encoding="utf-8"))
        report = validate_physical_evidence(unknown)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(report["physical_outcome"], "UNKNOWN")
        overstated = copy.deepcopy(unknown)
        overstated["status"] = "PASS"
        overstated["physical_test"] = True
        self.assertEqual(validate_physical_evidence(overstated)["outcome"], "FAIL")

        identity = "sha256:" + "a" * 64
        base = {
            "availability": "AVAILABLE",
            "boot_id": "boot-before",
            "session_generation": 3,
            "unit_enabled": "enabled",
            "unit_active": "active",
            "linger": "yes",
            "installation_identity": identity,
            "credential_identity": identity,
        }
        passed = {
            "schema_version": "mncs-fabric.fedora-reboot-acceptance.v0.1",
            "record_type": "mncs-fabric.fedora-reboot-acceptance",
            "status": "PASS",
            "physical_test": True,
            "controller_fabric_commit": "a" * 40,
            "worker_fabric_commit": "a" * 40,
            "controller_identity": "controller",
            "worker_identity": "worker",
            "worker_certificate_fingerprint": identity,
            "before": base,
            "after": {**base, "boot_id": "boot-after", "session_generation": 4},
            "controller_observed_reconnect_before_acceptance_ssh": True,
            "invariants": {
                "same_logical_identity": True,
                "higher_session_generation": True,
                "same_certificate_fingerprint": True,
                "same_installation_identity": True,
                "same_credential_identity": True,
                "registry_unchanged": True,
                "manual_worker_launch": False,
                "consumer_worker_endpoint_knowledge": False,
            },
            "execution": {
                "disposition": "EXECUTED",
                "worker_identity": "worker",
                "record_identity": identity,
                "receipt_identity": "b" * 64,
                "bundle_identity": "c" * 64,
                "archive_identity": identity,
            },
            "claim_boundary": "operator-controlled physical evidence; no attestation, semantic correctness, custody, independence, conformance, or certification claim",
            "limitations": ["operator-controlled"],
        }
        self.assertEqual(validate_physical_evidence(passed)["physical_outcome"], "PASS")
        passed["after"]["session_generation"] = 3
        self.assertEqual(validate_physical_evidence(passed)["outcome"], "FAIL")

    def test_windows_gpu_and_cross_os_evidence_validate(self) -> None:
        root = Path(__file__).parents[1] / "development-evidence"
        windows = json.loads((root / "windows-gpu-worker.json").read_text(encoding="utf-8"))
        heterogeneous = json.loads((root / "fedora-windows-heterogeneous.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_physical_evidence(windows)["outcome"], "PASS")
        self.assertEqual(validate_physical_evidence(heterogeneous)["outcome"], "PASS")
        tampered = copy.deepcopy(windows)
        tampered["runtime"]["execution_probe"] = "UNKNOWN"
        self.assertEqual(validate_physical_evidence(tampered)["outcome"], "FAIL")

    def test_offload_three_node_and_fault_evidence_validate(self) -> None:
        root = Path(__file__).parents[1] / "development-evidence"
        for name in ("windows-sequential-offload.json", "three-node-heterogeneous.json", "heterogeneous-fault-profiles.json"):
            evidence = json.loads((root / name).read_text(encoding="utf-8"))
            self.assertEqual(validate_physical_evidence(evidence)["outcome"], "PASS", name)
        offload = json.loads((root / "windows-sequential-offload.json").read_text(encoding="utf-8"))
        offload["offload_capability"]["actual_mode"] = "cpu"
        self.assertEqual(validate_physical_evidence(offload)["outcome"], "FAIL")

    def test_raspberry_pi_and_four_node_evidence_validate(self) -> None:
        root = Path(__file__).parents[1] / "development-evidence"
        for name in ("raspberry-pi-preflight-pass.json", "raspberry-pi-native-bundle.json", "four-node-heterogeneous.json"):
            evidence = json.loads((root / name).read_text(encoding="utf-8"))
            self.assertEqual(validate_physical_evidence(evidence)["outcome"], "PASS", name)
        tampered = json.loads((root / "four-node-heterogeneous.json").read_text(encoding="utf-8"))
        tampered["records"][0]["worker_identity"] = "raspberry-pi"
        self.assertEqual(validate_physical_evidence(tampered)["outcome"], "FAIL")
