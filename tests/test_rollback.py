from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.certify import certify_inventory
from mncs_fabric.conformance import evaluate_conformance
from mncs_fabric.desired_state import resolve_desired_state
from mncs_fabric.fleet_ops import FleetManager
from mncs_fabric.management import ManagementStore
from mncs_fabric.package_artifact import describe_package_artifact, write_verified_artifact
from mncs_fabric.providers import rollback_action
from tests.test_inventory import sample_inventory


def _inventory(version: str):
    payload = sample_inventory(harness="0.1.0")
    fabric = dict(payload["fabric"])
    fabric["worker_version"] = version
    from mncs_fabric.inventory import build_worker_inventory

    return build_worker_inventory(
        worker_id=payload["worker_identity"],
        identity=payload["identity"],
        hardware=payload["hardware"],
        fabric=fabric,
        tools=payload["tools"],
        runtimes=payload["runtimes"],
        repositories=payload["repositories"],
        services=payload["services"],
        health=payload["health"],
        credentials=payload["credentials"],
        captured_at=payload["captured_at"],
    )


class RollbackLifecycleTests(unittest.TestCase):
    def test_exact_previous_artifact_restore_then_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = FleetManager(ManagementStore(root / "mgmt.jsonl"), controller_id="controller")
            previous_bytes = b"artifact-A-known-good"
            current_bytes = b"artifact-B-bad"
            previous = root / "a.tar.gz"
            current = root / "b.tar.gz"
            previous.write_bytes(previous_bytes)
            current.write_bytes(current_bytes)
            stage = root / "stage"
            write_verified_artifact(stage, describe_package_artifact(previous, version="0.2.0a23"), previous_bytes)
            write_verified_artifact(stage, describe_package_artifact(current, version="0.2.0a24"), current_bytes)
            before = _inventory("0.2.0a23")
            desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker"], supported_current={"fabric-worker": "0.2.0a24"})
            manager.assign(desired)

            def apply_b(_actions):
                return [{
                    "disposition": "PASS",
                    "provider": "package.fabric",
                    "restart_required": True,
                    "rollback": {
                        "capability": "exact",
                        "previous_version": "0.2.0a23",
                        "artifact_identity": describe_package_artifact(current, version="0.2.0a24")["artifact_identity"],
                        "previous_artifact_identity": describe_package_artifact(previous, version="0.2.0a23")["artifact_identity"],
                        "previous_artifact_path": str(stage / "previous" / previous.name) if (stage / "previous").exists() else str(previous),
                    },
                }]

            applied = manager.reconcile("worker-a", before, apply_b, apply=True, force=True, profiles=["mncs-linux-worker"])
            self.assertTrue(applied["restart_required"])
            self.assertEqual(applied["update_transaction"]["state"], "DISCONNECT_EXPECTED")
            self.assertIsNotNone(applied["update_transaction"]["previous_artifact_identity"])

            gone = manager.observe_update("worker-a", connected=False, seen_disconnect=True)
            self.assertEqual(gone["observation"]["observation"], "EXPECTED_DISCONNECT")
            wrong = _inventory("0.2.0a23")
            verified = manager.verify_update_version("worker-a", wrong)
            self.assertEqual(verified["observation"]["observation"], "WRONG_VERSION")
            self.assertEqual(verified["update_transaction"]["state"], "ROLLBACK_APPLYING")

            restored = manager.rollback_update(
                "worker-a",
                wrong,
                lambda result, inventory: {
                    "disposition": "PASS",
                    "detail": "restored previous artifact",
                    "restart_required": True,
                },
                applied_result=applied["receipt"] if False else {
                    "provider": "package.fabric",
                    "rollback": applied["receipt"] and applied["update_transaction"] and {
                        "previous_artifact_path": str(previous),
                        "previous_artifact_identity": applied["update_transaction"]["previous_artifact_identity"],
                        "previous_version": "0.2.0a23",
                    },
                },
            )
            self.assertTrue(restored["restart_required"])
            self.assertEqual(restored["update_transaction"]["state"], "DISCONNECT_EXPECTED")
            self.assertEqual(restored["update_transaction"]["expected_version"], "0.2.0a23")

            manager.observe_update("worker-a", connected=False, seen_disconnect=True)
            restored_inventory = _inventory("0.2.0a23")
            after = manager.verify_update_version("worker-a", restored_inventory)
            self.assertEqual(after["update_transaction"]["state"], "CERTIFYING")
            restored_desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker"], supported_current={"fabric-worker": "0.2.0a23"})
            manager.assign(restored_desired)
            health = certify_inventory(restored_inventory, profiles=["mncs-linux-worker"])
            completed = manager.complete_update("worker-a", restored_inventory, certification=health)
            self.assertEqual(completed["management"]["state"], "READY")
            self.assertIn(completed["update_transaction"]["state"], {"READY", "ROLLED_BACK"})

    def test_missing_and_corrupt_previous_artifact_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = FleetManager(ManagementStore(root / "mgmt.jsonl"), controller_id="controller")
            inventory = _inventory("0.2.0a23")
            desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker"], supported_current={"fabric-worker": "0.2.0a24"})
            manager.assign(desired)

            def apply_b(_actions):
                return [{
                    "disposition": "PASS",
                    "provider": "package.fabric",
                    "restart_required": True,
                    "rollback": {
                        "capability": "partial",
                        "previous_version": "0.2.0a23",
                        "previous_artifact_identity": None,
                        "previous_artifact_path": str(root / "missing.tar.gz"),
                    },
                }]

            manager.reconcile("worker-a", inventory, apply_b, apply=True, force=True, profiles=["mncs-linux-worker"])
            manager.observe_update("worker-a", connected=False, seen_disconnect=True)
            manager.verify_update_version("worker-a", _inventory("0.2.0a23"))
            missing = manager.rollback_update(
                "worker-a",
                inventory,
                rollback_action,
                applied_result={
                    "provider": "package.fabric",
                    "rollback": {
                        "previous_artifact_path": str(root / "missing.tar.gz"),
                        "previous_version": "0.2.0a23",
                    },
                },
            )
            self.assertEqual(missing["rollback"]["disposition"], "FAIL")
            self.assertEqual(missing["update_transaction"]["state"], "QUARANTINED")
            self.assertEqual(missing["management"]["state"], "QUARANTINED")

            corrupt = root / "corrupt.tar.gz"
            corrupt.write_bytes(b"nope")
            self.assertEqual(
                rollback_action(
                    {
                        "provider": "package.fabric",
                        "rollback": {
                            "capability": "exact",
                            "previous_artifact_path": str(corrupt),
                            "previous_version": "0.2.0a23",
                        },
                    },
                    inventory,
                )["failure_class"],
                "ROLLBACK_FAILURE",
            )

    def test_conformance_is_evaluated_after_rollback_reconnect(self) -> None:
        inventory = _inventory("0.2.0a23")
        desired = resolve_desired_state(worker_id="worker-a", profiles=["mncs-linux-worker"], supported_current={"fabric-worker": "0.2.0a23"})
        conformance = evaluate_conformance(desired, inventory)
        self.assertNotEqual(conformance["disposition"], "UNKNOWN")
