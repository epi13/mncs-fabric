from __future__ import annotations

import unittest

from mncs_fabric.certify import certify_inventory, select_inference_models
from mncs_fabric.conformance import decide_ready_state, evaluate_conformance, validate_conformance
from mncs_fabric.desired_state import resolve_desired_state
from tests.test_inventory import sample_inventory


class ConformanceTests(unittest.TestCase):
    def test_missing_required_git_is_nonconformant_and_blocks_ready(self) -> None:
        inventory = sample_inventory(git=False, harness="0.1.0")
        desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-windows-worker"], supported_current={"fabric-worker": "0.2.0a21"})
        conformance = validate_conformance(evaluate_conformance(desired, inventory))
        self.assertEqual(conformance["disposition"], "NONCONFORMANT")
        self.assertIn("tool:git", conformance["blocking_failures"])
        health = certify_inventory(inventory, profiles=["mncs-windows-worker"])
        self.assertEqual(health["disposition"], "CERTIFIED")
        repo = next(layer for layer in health["layers"] if layer["name"] == "repository_access")
        self.assertFalse(repo["applicable"])
        decision = decide_ready_state(health, conformance)
        self.assertEqual(decision["state"], "DEGRADED")
        self.assertEqual(decision["certification_status"], "CERTIFIED")

    def test_unauthenticated_gh_is_advisory_nonconformance(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        payload = {key: value for key, value in inventory.items() if key != "inventory_identity"}
        payload["credentials"] = [
            {"name": "github-cli", "available": False, "detail": "unauthenticated-or-unavailable"},
            {"name": "joern", "available": False, "detail": "absent"},
            {"name": "forge", "available": False, "detail": "absent"},
        ]
        from mncs_fabric.inventory import build_worker_inventory

        rebuilt = build_worker_inventory(
            worker_id=payload["worker_identity"],
            identity=payload["identity"],
            hardware=payload["hardware"],
            fabric=payload["fabric"],
            tools=payload["tools"],
            runtimes=payload["runtimes"],
            repositories=payload["repositories"],
            services=payload["services"],
            health=payload["health"],
            credentials=payload["credentials"],
            captured_at=payload["captured_at"],
        )
        desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker"], supported_current={"fabric-worker": "0.2.0a21"})
        conformance = evaluate_conformance(desired, rebuilt)
        gh = next(item for item in conformance["requirements"] if item["name"] == "gh")
        self.assertEqual(gh["status"], "AUTH_REQUIRED")
        self.assertFalse(gh["blocking"])
        self.assertNotIn("tool:gh", conformance["blocking_failures"])
        health = certify_inventory(rebuilt, profiles=["mncs-linux-worker"])
        decision = decide_ready_state(health, conformance)
        self.assertEqual(decision["state"], "READY")

    def test_build_profile_missing_joern_and_forge_blocks_ready(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker", "mncs-build-worker"], supported_current={"fabric-worker": "0.2.0a21"})
        conformance = evaluate_conformance(desired, inventory)
        self.assertEqual(conformance["disposition"], "NONCONFORMANT")
        self.assertTrue(any(item.startswith("tool:joern") or item.startswith("tool:forge") for item in conformance["blocking_failures"]))
        health = certify_inventory(inventory, profiles=["mncs-linux-worker", "mncs-build-worker"])
        self.assertEqual(health["disposition"], "CERTIFIED")
        decision = decide_ready_state(health, conformance)
        self.assertEqual(decision["state"], "DEGRADED")

    def test_inference_profile_without_ollama_is_health_failure(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        payload = {key: value for key, value in inventory.items() if key != "inventory_identity"}
        payload["runtimes"] = [{
            "name": "ollama", "present": False, "install_type": "absent", "service_type": "absent",
            "endpoint": None, "version": None, "reachable": False, "models": [],
        }]
        from mncs_fabric.inventory import build_worker_inventory

        rebuilt = build_worker_inventory(
            worker_id=payload["worker_identity"],
            identity=payload["identity"],
            hardware=payload["hardware"],
            fabric=payload["fabric"],
            tools=payload["tools"],
            runtimes=payload["runtimes"],
            repositories=payload["repositories"],
            services=[item for item in payload["services"] if item["name"] != "ollama"] + [{
                "name": "ollama", "present": False, "manager": "absent", "unit": None, "state": "absent", "install_type": "absent",
            }],
            health=payload["health"],
            credentials=payload["credentials"],
            captured_at=payload["captured_at"],
        )
        health = certify_inventory(rebuilt, profiles=["mncs-inference-worker"])
        self.assertEqual(health["disposition"], "FAILED")
        desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-inference-worker"], supported_current={"fabric-worker": "0.2.0a21"})
        conformance = evaluate_conformance(desired, rebuilt)
        decision = decide_ready_state(health, conformance)
        self.assertEqual(decision["state"], "QUARANTINED")

    def test_optional_capability_missing_does_not_fail_health(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        health = certify_inventory(inventory, profiles=["mncs-linux-worker"])
        forge = next(layer for layer in health["layers"] if layer["name"] == "forge")
        self.assertFalse(forge["applicable"])
        self.assertEqual(health["disposition"], "CERTIFIED")

    def test_desired_models_are_selected_independently_of_inventory_order(self) -> None:
        inventory = sample_inventory(models=[
            {"name": "first:latest", "digest": None, "size_bytes": 1, "family": None, "parameter_size": None, "quantization": None},
            {"name": "wanted:7b", "digest": None, "size_bytes": 1, "family": None, "parameter_size": None, "quantization": None},
        ])
        generic = select_inference_models(inventory, desired_models=None)
        self.assertEqual(generic, ["first:latest"])
        wanted = select_inference_models(inventory, desired_models=["wanted"])
        self.assertEqual(wanted, ["wanted:7b"])
        missing = select_inference_models(inventory, desired_models=["absent-model"])
        self.assertEqual(missing, ["absent-model"])
