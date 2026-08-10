from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mncs_fabric.api import FabricClient
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.models import validate_job_plan
from mncs_fabric.scheduler import WorkerSlot


class ExecutionBundleBindingTests(unittest.TestCase):
    def test_transfer_report_is_not_sent_as_dispatch_binding(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('ok')\n", encoding="utf-8")
            manifest = build_manifest(bundle)
            plan = validate_job_plan(
                {
                    "schema_version": "mncs-fabric.job-plan.v0.1",
                    "job_id": "binding-regression",
                    "candidate_identity": "sha256:" + "a" * 64,
                    "evaluator_identity": None,
                    "artifact_manifest_identity": manifest["manifest_identity"],
                    "argv": ["@python", "task.py"],
                    "working_directory": ".",
                    "timeout_seconds": 5,
                    "output_limit_bytes": 4096,
                    "environment": {"PYTHONHASHSEED": "0"},
                    "required_capabilities": ["python"],
                    "result_paths": [],
                    "network_policy": "DECLARED_OFFLINE",
                }
            )
            client = FabricClient("binding-controller", root / "controller.jsonl")
            client.remote_configs["remote-worker"] = object()  # type: ignore[assignment]
            client.network.remote_workers["remote-worker"] = (
                object(),
                WorkerSlot(worker_id="remote-worker", capabilities=frozenset({"python"})),
            )
            archive = root / "probe.zip"
            archive.write_bytes(b"fixture")
            binding = {
                "bundle_identity": "b" * 64,
                "archive_identity": "sha256:" + "c" * 64,
            }
            transfer_report = {
                "status": "COMMITTED",
                **binding,
                "transfer_id": "transfer-fixture",
                "valid": True,
                "manifest": {"fixture": True},
            }

            def fake_ensure(worker_id: str, archive_path: Path, **_kwargs: object) -> dict[str, object]:
                self.assertEqual(worker_id, "remote-worker")
                self.assertEqual(archive_path, archive)
                client.bundle_links[worker_id] = dict(binding)
                return dict(transfer_report)

            captured: dict[str, object] = {}

            def fake_dispatch(*_args: object, **kwargs: object) -> dict[str, object]:
                captured["execution_bundle"] = kwargs.get("execution_bundle")
                return {
                    "worker_id": "remote-worker",
                    "request_id": "request-fixture",
                    "payload": {"disposition": "UNKNOWN", "record": None},
                }

            client.ensure_bundle = fake_ensure  # type: ignore[method-assign]
            client.network.dispatch_via = fake_dispatch  # type: ignore[method-assign]

            client.execute(
                plan,
                manifest,
                worker_id="remote-worker",
                execution_bundle_archive=archive,
            )

            self.assertEqual(captured["execution_bundle"], binding)
            self.assertEqual(set(captured["execution_bundle"]), {"bundle_identity", "archive_identity"})


if __name__ == "__main__":
    unittest.main()
