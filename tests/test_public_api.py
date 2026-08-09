from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from mncs_fabric import __version__

from mncs_fabric.api import ConsumerContext, FabricClient, LocalWorkerConfig, PlacementRequest
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.canonical import verify_identity
from mncs_fabric.models import validate_job_plan
from mncs_fabric.worker import LocalWorker


def _plan(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    manifest = build_manifest(root)
    plan = validate_job_plan({
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "public:fixture",
        "candidate_identity": "sha256:" + "a" * 64,
        "evaluator_identity": None,
        "artifact_manifest_identity": manifest["manifest_identity"],
        "argv": ["@python", "task.py"],
        "working_directory": ".",
        "timeout_seconds": 5,
        "output_limit_bytes": 4096,
        "environment": {"PYTHONHASHSEED": "0"},
        "required_capabilities": ["python"],
        "result_paths": ["result.json"],
        "network_policy": "DECLARED_OFFLINE",
    })
    return plan, manifest


class PublicContractTests(unittest.TestCase):
    def test_contract_is_deterministic_and_identity_addressable(self) -> None:
        first = FabricClient.contract()
        second = FabricClient.contract()
        self.assertEqual(first, second)
        self.assertTrue(verify_identity(first, "contract_identity"))
        self.assertTrue(first["features"]["native_bundle_transfer"])

    def test_local_consumer_execution_owns_receipt_and_provenance(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('{\\\"ok\\\":true}')\n", encoding="utf-8")
            plan, manifest = _plan(bundle)
            client = FabricClient("consumer-controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorkerConfig("worker-a", bundle, root / "worker.jsonl"))
            context = ConsumerContext(
                source_project="MNEL",
                consumer_workload_identity="sha256:" + "b" * 64,
                experiment_identity="sha256:" + "c" * 64,
                forge_workflow_identity="sha256:" + "d" * 64,
            )
            results = client.execute(plan, manifest, worker_id="worker-a", consumer_context=context)
            self.assertEqual(len(results), 1)
            result = results[0]
            self.assertEqual(result["disposition"], "EXECUTED")
            self.assertEqual(client.verify_receipt(result["receipt"])["outcome"], "PASS")
            self.assertEqual(result["consumer_context_identity"], context.context_identity)
            self.assertTrue(verify_identity(result["provenance_binding"], "binding_identity"))
            self.assertEqual(client.reconcile(results, require_distinct_nodes=False)["outcome"], "PASS")

    def test_replication_and_unknown_missing_result_are_public(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('ok')\n", encoding="utf-8")
            plan, manifest = _plan(bundle)
            client = FabricClient("replication-controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorker("worker-a", bundle, root / "a.jsonl"))
            client.register_local_worker(LocalWorker("worker-b", bundle, root / "b.jsonl"))
            results = client.replicate(plan, manifest, replicas=2, consumer_context=ConsumerContext("RAVEL", "sha256:" + "e" * 64))
            self.assertEqual([item["worker_identity"] for item in results], ["worker-a", "worker-b"])
            self.assertEqual(client.reconcile(results)["outcome"], "PASS")
            self.assertEqual(client.reconcile(results + [{"disposition": "UNKNOWN"}])["outcome"], "UNKNOWN")

    def test_public_api_returns_fabric_owned_placement_admission_and_receipt_reference(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('placement')\n", encoding="utf-8")
            plan, manifest = _plan(bundle)
            client = FabricClient("placement-controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorkerConfig("worker-placement", bundle, root / "worker.jsonl"))
            result = client.execute(plan, manifest, worker_id="worker-placement", placement=PlacementRequest(execution_device="cpu"))[0]
            self.assertEqual(result["placement_admission"]["admission_mode"], "cpu")
            self.assertEqual(result["placement_admission"]["worker_identity"], "worker-placement")
            reference = result["receipt"]["placement"]["execution_placement_reference"]
            self.assertEqual(reference["placement_request_identity"], PlacementRequest(execution_device="cpu").placement_request_identity)
            self.assertEqual(result["receipt"]["runner"]["runner_version"], __version__)
