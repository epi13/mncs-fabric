from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mncs_fabric.api import FabricClient, LocalWorkerConfig, PlacementRequest
from mncs_fabric.canonical import verify_identity
from mncs_fabric.runtime import (
    build_runtime_observation,
    build_runtime_profile,
    runtime_observation_is_fresh,
    validate_runtime_observation,
    validate_runtime_profile,
)
from mncs_fabric.worker import LocalWorker
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.models import validate_job_plan


class RuntimeContractTests(unittest.TestCase):
    def test_profile_is_portable_and_identity_addressable(self) -> None:
        profile = build_runtime_profile("worker", executable=Path(__import__("sys").executable), captured_at="2026-01-01T00:00:00Z")
        self.assertNotIn("executable", profile)
        self.assertTrue(verify_identity(profile, "runtime_profile_identity"))
        self.assertEqual(validate_runtime_profile(profile)["worker_identity"], "worker")

    def test_probe_requires_real_execution_status_but_accepts_unknown_fixture(self) -> None:
        profile = build_runtime_profile("gpu-worker", captured_at="2026-01-01T00:00:00Z")
        observation = build_runtime_observation(
            worker_identity="gpu-worker",
            runtime_profile=profile,
            probe={
                "python_version": profile["python_version"],
                "accelerator_backend": "cuda",
                "accelerator": "fixture-gpu",
                "runtime_version": "fixture-cuda",
                "execution_probe": "PASS",
                "precision_probes": {"float32": "PASS", "float16": "UNKNOWN"},
                "captured_at": "2026-01-01T00:00:00Z",
            },
            captured_at="2026-01-01T00:00:00Z",
        )
        self.assertEqual(validate_runtime_observation(observation, expected_worker_id="gpu-worker")["runtime_execution_probe"], "PASS")
        self.assertTrue(runtime_observation_is_fresh(observation, now="2026-01-01T00:30:00Z", max_age_seconds=3600))
        with self.assertRaises(Exception):
            validate_runtime_observation({**observation, "worker_identity": "other"}, expected_worker_id="gpu-worker")

    def test_worker_description_and_public_binding_use_runtime_identity(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("runtime-worker", bundle, root / "worker.jsonl")
            description = worker.description()
            profile = validate_runtime_profile(description["runtime_profile"], expected_worker_id="runtime-worker")
            client = FabricClient("runtime-controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorkerConfig("runtime-worker", bundle, root / "client-worker.jsonl"))
            observation = client.ingest_runtime_observation(
                "runtime-worker",
                {"execution_probe": "UNKNOWN", "precision_probes": {}, "accelerator_backend": None},
                runtime_profile=profile,
                captured_at="2026-01-01T00:00:00Z",
            )
            result = {"worker_identity": "runtime-worker", "request_identity": "request-1", "record_identity": "sha256:" + "b" * 64, "receipt_identity": "sha256:" + "c" * 64}
            binding = client.bind_runtime_observation(result, observation)
            self.assertTrue(verify_identity(binding, "runtime_binding_identity"))
            self.assertEqual(binding["runtime_profile_identity"], profile["runtime_profile_identity"])

    def test_public_dispatch_returns_runtime_observation_binding(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('ok')\n", encoding="utf-8")
            manifest = build_manifest(bundle)
            plan = validate_job_plan({
                "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "runtime:dispatch",
                "candidate_identity": "sha256:" + "a" * 64, "evaluator_identity": None,
                "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"],
                "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096,
                "environment": {}, "required_capabilities": ["python"], "result_paths": ["result.json"],
                "network_policy": "DECLARED_OFFLINE",
            })
            client = FabricClient("runtime-dispatch-controller", root / "controller.jsonl")
            client.register_local_worker(LocalWorkerConfig("runtime-dispatch-worker", bundle, root / "worker.jsonl"))
            profile = client.runtime_profile("runtime-dispatch-worker")
            observation = client.ingest_runtime_observation("runtime-dispatch-worker", {"execution_probe": "UNKNOWN", "precision_probes": {}, "accelerator_backend": None}, runtime_profile=profile)
            result = client.execute(plan, manifest, worker_id="runtime-dispatch-worker", placement=PlacementRequest(execution_device="cpu"))[0]
            self.assertEqual(result["disposition"], "EXECUTED")
            self.assertEqual(result["runtime_observation"]["runtime_observation_identity"], observation["runtime_observation_identity"])
            self.assertEqual(result["runtime_binding"]["record_identity"], result["record_identity"])


if __name__ == "__main__":
    unittest.main()
