from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.canonical import sha256_identity
from mncs_fabric.cli import build_parser, main
from mncs_fabric.controller import LocalController, NetworkController
from mncs_fabric.models import validate_job_plan
from mncs_fabric.protocol import make_envelope, validate_envelope
from mncs_fabric.transport import InProcessTransport
from mncs_fabric.worker import LocalWorker


def _plan(root: Path):
    manifest = build_manifest(root)
    plan = validate_job_plan({
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "fleet:job",
        "candidate_identity": "sha256:" + "a" * 64,
        "evaluator_identity": None,
        "artifact_manifest_identity": manifest["manifest_identity"],
        "argv": ["@python", "-c", "print('ok')"],
        "working_directory": ".",
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
        "environment": {},
        "required_capabilities": ["python"],
        "result_paths": [],
        "network_policy": "UNSPECIFIED",
    })
    return plan, manifest


class FleetManagementTests(unittest.TestCase):
    def test_inventory_and_plan_over_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("fleet-worker", bundle, root / "worker.jsonl")
            controller = LocalController("fleet-controller", root / "controller.jsonl")
            controller.register(worker)
            inspected = controller.inspect_worker("fleet-worker")
            self.assertEqual(inspected["inventory"]["worker_identity"], "fleet-worker")
            plan = controller.plan_worker("fleet-worker", profiles=["mncs-linux-worker"])
            self.assertEqual(plan["worker_identity"], "fleet-worker")
            self.assertIn("actions", plan)

    def test_plan_only_reconcile_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("fleet-worker", bundle, root / "worker.jsonl")
            controller = LocalController("fleet-controller", root / "controller.jsonl")
            controller.register(worker)
            first = controller.reconcile_worker("fleet-worker", apply=False, profiles=["mncs-linux-worker"])
            second = controller.reconcile_worker("fleet-worker", apply=False, profiles=["mncs-linux-worker"])
            self.assertEqual(first["plan"]["change_count"], second["plan"]["change_count"])
            self.assertEqual(first["receipt"]["mode"], "plan")

    def test_drain_blocks_dispatch_and_resume_requires_certification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('ok')\n", encoding="utf-8")
            worker = LocalWorker("fleet-worker", bundle, root / "worker.jsonl")
            controller = LocalController("fleet-controller", root / "controller.jsonl")
            controller.register(worker)
            controller.drain_worker("fleet-worker", reason="test drain")
            self.assertFalse(worker.accepts_work())
            plan, manifest = _plan(bundle)
            result = controller.dispatch(plan, manifest)
            self.assertEqual(result[0]["disposition"], "UNKNOWN")
            certified = controller.certify_worker("fleet-worker", profiles=["mncs-linux-worker"])
            if certified["disposition"] == "CERTIFIED":
                controller.resume_worker("fleet-worker", reason="test resume")
                self.assertTrue(worker.accepts_work())
            else:
                with self.assertRaises(Exception):
                    if certified["disposition"] == "FAILED":
                        controller.fleet_manager.resume("fleet-worker")

    def test_network_controller_uses_same_typed_messages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("remote-fleet", bundle, root / "worker.jsonl")
            controller = NetworkController("net-controller", root / "controller.jsonl")
            controller.register_remote("remote-fleet", worker.capabilities(), InProcessTransport(worker))
            inventory = controller.inventory_via(InProcessTransport(worker), worker_id="remote-fleet")
            self.assertEqual(inventory["worker_identity"], "remote-fleet")

    def test_raw_shell_is_not_a_protocol_message(self) -> None:
        with self.assertRaises(Exception):
            make_envelope(
                "worker.exec.request",
                controller_id="c",
                worker_id="w",
                request_id="r" * 16,
                job_id="j",
                nonce="n" * 16,
                payload={"command": "rm -rf /"},
                created_at="2026-08-14T00:00:00Z",
                expires_at="2026-08-14T00:01:00Z",
            )

    def test_cli_local_inspect_and_plan(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["worker", "inspect", "--local", "--label", "cli-worker", "--json"])
        self.assertEqual(args.worker_command, "inspect")
        code = main(["worker", "inspect", "--local", "--label", "cli-worker", "--json"])
        self.assertEqual(code, 0)
        code = main(["worker", "plan", "--local", "--label", "cli-worker", "--profile", "mncs-linux-worker", "--json"])
        self.assertEqual(code, 0)
        code = main(["node", "inspect", "--label", "cli-node"])
        self.assertEqual(code, 0)

    def test_quarantine_is_not_schedulable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("fleet-worker", bundle, root / "worker.jsonl")
            controller = LocalController("fleet-controller", root / "controller.jsonl")
            controller.register(worker)
            controller.quarantine_worker("fleet-worker", reason="failed cert")
            self.assertEqual(worker.management_state()["state"], "QUARANTINED")
            self.assertFalse(controller.fleet_manager.status("fleet-worker")["schedulable"])
