from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mncs_fabric.desired_state import resolve_desired_state
from mncs_fabric.errors import ValidationError
from mncs_fabric.maintenance import (
    apply_maintenance_plan,
    build_maintenance_plan,
    complete_receipt,
    format_plan,
    operational_knowledge,
    validate_maintenance_plan,
    validate_maintenance_receipt,
)
from mncs_fabric.providers import apply_action, plan_action_from_change, validate_action
from tests.test_inventory import sample_inventory


class MaintenanceTests(unittest.TestCase):
    def _desired(self, worker_id: str = "worker-a", version: str = "0.2.0a21"):
        return resolve_desired_state(
            worker_id=worker_id,
            profiles=["mncs-linux-worker", "mncs-inference-worker"],
            supported_current={"fabric-worker": version},
            captured_at="2026-08-14T00:00:00Z",
        )

    def test_plan_is_noop_when_compliant(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        plan = build_maintenance_plan(worker_id="worker-a", desired=self._desired(), inventory=inventory)
        checked = validate_maintenance_plan(plan)
        self.assertEqual(checked["change_count"], 0)
        self.assertIn("NO CHANGES REQUIRED", format_plan(checked))
        receipt = apply_maintenance_plan(checked, inventory, apply=True)
        self.assertEqual(validate_maintenance_receipt(receipt)["disposition"], "NO_CHANGES")

    def test_plan_classifies_ollama_rediscovery_and_missing_joern(self) -> None:
        inventory = sample_inventory(ollama_manager="unknown")
        desired = resolve_desired_state(
            worker_id="worker-a",
            profiles=["mncs-linux-worker", "mncs-build-worker", "mncs-inference-worker"],
            supported_current={"fabric-worker": "0.2.0a21"},
            captured_at="2026-08-14T00:00:00Z",
        )
        plan = build_maintenance_plan(worker_id="worker-a", desired=desired, inventory=inventory)
        providers = {item["provider"] for item in plan["actions"]}
        self.assertIn("tool.joern", providers)
        self.assertTrue(any(item["authorization"] in {"privilege", "none", "operator"} for item in plan["actions"]))

    def test_critical_disk_is_a_typed_preflight_failure(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        payload = {key: value for key, value in inventory.items() if key != "inventory_identity"}
        payload["health"] = dict(payload["health"])
        payload["health"]["disk_pressure"] = "critical"
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
        desired = self._desired(version="9.9.9")
        plan = build_maintenance_plan(worker_id="worker-a", desired=desired, inventory=rebuilt)
        self.assertFalse(plan["preflight_passed"])
        self.assertTrue(any(item["failure_class"] == "DISK_FAILURE" for item in plan["preflight"]))

    def test_active_workload_blocks_disruptive_apply(self) -> None:
        inventory = sample_inventory()
        desired = self._desired(version="9.9.9")
        plan = build_maintenance_plan(worker_id="worker-a", desired=desired, inventory=inventory, active_jobs=2)
        self.assertFalse(plan["preflight_passed"])
        receipt = apply_maintenance_plan(plan, inventory, apply=True)
        self.assertEqual(receipt["disposition"], "FAIL")
        self.assertEqual(receipt["failure_class"], "ACTIVE_WORKLOAD")

    def test_privilege_actions_are_not_auto_applied(self) -> None:
        action = validate_action({
            "action": "install",
            "target": "joern",
            "update_class": "B",
            "provider": "tool.joern",
            "disruptive": False,
            "rollback": "unsupported",
            "authorization": "privilege",
            "current": "absent",
            "desired": "mncs-supported",
            "reason": "missing",
        })
        result = apply_action(action, sample_inventory())
        self.assertEqual(result["disposition"], "SKIPPED")
        self.assertEqual(result["failure_class"], "PRIVILEGE_REQUIRED")

    def test_unknown_ollama_manager_is_rediscovered_not_systemctl(self) -> None:
        change = {
            "kind": "runtime",
            "name": "ollama",
            "update_class": "C",
            "desired": "mncs-supported",
            "actual": "present",
            "authorization": "none",
            "detail": "manager unknown",
        }
        action = plan_action_from_change(change)
        self.assertEqual(action["action"], "rediscover")
        with patch("mncs_fabric.providers.discover_service", return_value={"name": "ollama", "present": True, "manager": "process", "unit": "127.0.0.1:11434", "state": "running", "install_type": "unknown"}), patch("mncs_fabric.providers.collect_ollama_models", return_value=([], None)):
            result = apply_action(action, sample_inventory(ollama_manager="unknown"))
        self.assertIn(result["disposition"], {"PASS", "FAIL"})
        self.assertNotIn("systemctl restart ollama", result["detail"])

    def test_receipt_redacts_and_is_self_identifying(self) -> None:
        inventory = sample_inventory(harness="0.1.0")
        plan = build_maintenance_plan(worker_id="worker-a", desired=self._desired(), inventory=inventory)
        receipt = complete_receipt(plan, inventory, [], mode="plan")
        checked = validate_maintenance_receipt(receipt)
        self.assertEqual(checked["disposition"], "NO_CHANGES")
        tampered = dict(checked)
        tampered["disposition"] = "PASS"
        with self.assertRaises(ValidationError):
            validate_maintenance_receipt(tampered)

    def test_fabric_package_plan_pins_controller_version(self) -> None:
        inventory = sample_inventory()
        desired = self._desired(version="0.2.0a23")
        plan = build_maintenance_plan(worker_id="worker-a", desired=desired, inventory=inventory)
        fabric = next(item for item in plan["actions"] if item["provider"] == "package.fabric")
        self.assertEqual(fabric["desired"], "0.2.0a23")
        self.assertEqual(fabric["authorization"], "operator")

    def test_operator_fabric_update_uses_staged_source(self) -> None:
        inventory = sample_inventory()
        action = validate_action({
            "action": "update",
            "target": "fabric-worker",
            "update_class": "A",
            "provider": "package.fabric",
            "disruptive": True,
            "rollback": "partial",
            "authorization": "operator",
            "current": "version-drift",
            "desired": "0.2.0a23",
            "reason": "pin",
        })
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / "mncs-fabric-0.2.0a23.tar.gz"
            staged.write_text("sdist", encoding="utf-8")
            with patch("mncs_fabric.supervisor.default_stage_dir", return_value=Path(directory)), patch("mncs_fabric.supervisor.apply_staged_upgrade", return_value={"disposition": "PASS", "detail": "activated staged", "stdout": "", "stderr": ""}), patch("mncs_fabric.supervisor.inspect_supervisor", return_value={"kind": "process", "python_executable": "python"}):
                result = apply_action(action, inventory)
        self.assertEqual(result["disposition"], "PASS")
        self.assertTrue(result["restart_required"])

    def test_missing_local_harness_is_advisory_not_blocking(self) -> None:
        inventory = sample_inventory(harness=None)
        desired = self._desired(version="0.2.0a21")
        plan = build_maintenance_plan(worker_id="worker-a", desired=desired, inventory=inventory)
        targets = {item["target"] for item in plan["actions"]}
        self.assertIn("local-harness", targets)
        from mncs_fabric.maintenance import partition_apply_actions

        worker_actions, advisory = partition_apply_actions(plan["actions"])
        self.assertTrue(any(item["target"] == "local-harness" for item in advisory))
        self.assertFalse(any(item["target"] == "local-harness" for item in worker_actions))
        action = next(item for item in plan["actions"] if item["target"] == "local-harness")
        result = apply_action(action, inventory)
        self.assertEqual(result["disposition"], "SKIPPED")
        self.assertEqual(result["failure_class"], "PRIVILEGE_REQUIRED")
        receipt = complete_receipt(plan, inventory, [result], mode="apply")
        self.assertNotEqual(receipt["disposition"], "FAIL")

    def test_advisory_verify_does_not_fail_fabric_apply_receipt(self) -> None:
        inventory = sample_inventory(harness=None)
        fabric = validate_action({
            "action": "update",
            "target": "fabric-worker",
            "update_class": "A",
            "provider": "package.fabric",
            "disruptive": True,
            "rollback": "partial",
            "authorization": "operator",
            "current": "0.2.0a28",
            "desired": "0.2.0a30",
            "reason": "pin",
        })
        harness = validate_action({
            "action": "verify",
            "target": "local-harness",
            "update_class": "A",
            "provider": "tool.inspect",
            "disruptive": False,
            "rollback": "unsupported",
            "authorization": "privilege",
            "current": "absent",
            "desired": "present",
            "reason": "harness package not importable",
        })
        fabric_result = {
            **{key: fabric[key] for key in ("action", "target", "provider")},
            "disposition": "PASS",
            "failure_class": None,
            "detail": "activated staged",
            "changed": True,
            "restart_required": True,
        }
        harness_result = apply_action(harness, inventory)
        receipt = complete_receipt(
            {"actions": [fabric, harness], "plan_identity": "sha256:" + ("ab" * 32),
             "worker_identity": "worker-a", "controller_identity": "controller",
             "desired_state_identity": "sha256:" + ("cd" * 32)},
            inventory,
            [fabric_result, harness_result],
            mode="apply",
        )
        self.assertEqual(receipt["disposition"], "PASS")

    def test_commons_knowledge_only_for_unusual_discoveries(self) -> None:
        systemd = sample_inventory(ollama_manager="systemd-system")
        process = sample_inventory(ollama_manager="process")
        self.assertEqual(operational_knowledge(systemd), [])
        kinds = {item["kind"] for item in operational_knowledge(process)}
        self.assertIn("Finding", kinds)
        self.assertIn("Decision", kinds)
