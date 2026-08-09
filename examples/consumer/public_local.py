"""Run a semantic-neutral workload through Fabric's public consumer API."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from mncs_fabric.api import ConsumerContext, FabricClient, LocalWorkerConfig
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.models import validate_job_plan
from mncs_fabric.models import validate_job_plan


ROOT = Path(__file__).parents[1] / "portable-python" / "bundle"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mncs-fabric-consumer-") as directory:
        state = Path(directory)
        bundle = state / "bundle"
        bundle.mkdir()
        (bundle / "task.py").write_bytes((ROOT / "task.py").read_bytes())
        manifest = build_manifest(bundle)
        plan = validate_job_plan({
            "schema_version": "mncs-fabric.job-plan.v0.1",
            "job_id": "consumer-fixture:local",
            "candidate_identity": "sha256:" + "a" * 64,
            "evaluator_identity": None,
            "artifact_manifest_identity": manifest["manifest_identity"],
            "argv": ["@python", "task.py"],
            "working_directory": ".",
            "timeout_seconds": 10,
            "output_limit_bytes": 65536,
            "environment": {},
            "required_capabilities": ["python"],
            "result_paths": ["result.json"],
            "network_policy": "DECLARED_OFFLINE",
        })
        client = FabricClient("consumer-fixture-controller", state / "controller.jsonl")
        client.register_local_worker(LocalWorkerConfig("consumer-fixture-worker", bundle, state / "worker.jsonl"))
        result = client.execute(
            plan,
            manifest,
            worker_id="consumer-fixture-worker",
            consumer_context=ConsumerContext("fixture", "sha256:" + "1" * 64, forge_workflow_identity="sha256:" + "2" * 64),
        )[0]
        print(json.dumps({"disposition": result["disposition"], "record_identity": result["record_identity"], "receipt_identity": result["receipt_identity"], "provenance_binding": result.get("provenance_binding")}, sort_keys=True))
    return 0 if result["disposition"] == "EXECUTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
