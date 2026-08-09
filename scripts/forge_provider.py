#!/usr/bin/env python3
"""Bounded Forge Provider Protocol adapter for project-local Fabric validation."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

PROVIDER = {"id": "mncs-fabric-local", "name": "MNCS Fabric local validation", "identity": "mncs-fabric-local-v1", "version": "0.7"}
SUPPORTED_CONSTRUCTS = ["fabric-unit-suite", "fabric-compile", "portable-example", "receipt-compatibility", "execution-bundle-compatibility", "execution-challenge-compatibility", "bounded-protocol-framing", "tls-loopback", "enrollment-revocation", "replay-adversarial", "scheduler-reconciliation", "resource-observation", "placement-admission", "runtime-aware-placement", "placement-evidence", "runtime-capability-evidence", "sequential-offload-evidence", "remote-worker-description", "remote-resource-refresh", "worker-liveness", "execution-collection", "collection-completeness", "physical-fault-corpus", "heterogeneous-fault-profiles", "three-node-heterogeneous-collection", "raspberry-pi-arm-preflight", "two-host-harness-static-validation", "two-host-evidence-validation", "persistent-worker-evidence", "windows-gpu-worker-evidence", "heterogeneous-cross-os-evidence", "public-contract-validation", "public-consumer-api", "consumer-provenance-binding", "native-bundle-transfer", "bundle-cache-integrity", "runtime-profile-validation", "runtime-observation-validation", "windows-worker-launcher-static-validation"]


def response(request: dict[str, object], status: str, summary: str, *, limitations: list[str] | None = None, witnesses: list[object] | None = None) -> dict[str, object]:
    return {"protocol_version": "0.1", "type": "analysis_response", "request_id": request.get("request_id", "forge-local"), "provider": PROVIDER, "status": status, "summary": summary, "witnesses": witnesses or [], "limitations": limitations or [], "extensions": {"unsupported": [], "mncs_forge": {"assumptions": ["validation is operator-controlled development evidence"], "dependency_envelope": {"paths": ["src", "tests", "schemas"], "identities": {}, "complete": False}}}}


def run_validation() -> tuple[str, str, list[object]]:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        result_stream = io.StringIO()
        result = unittest.TextTestRunner(stream=result_stream, verbosity=0).run(suite)
    if not result.wasSuccessful():
        failures = [{"test": str(test), "diagnostic": error.splitlines()[-1] if error.splitlines() else ""} for test, error in result.failures + result.errors]
        return "FAIL", "Fabric unit/integration suite failed", [{"failures": len(result.failures), "errors": len(result.errors), "cases": failures}]
    import compileall
    if not compileall.compile_dir(str(ROOT / "src"), quiet=1):
        return "FAIL", "Fabric source compilation failed", []
    from mncs_fabric.artifacts import verify_manifest
    from mncs_fabric.contracts import build_public_contract, validate_public_contract
    from mncs_fabric.evidence import validate_physical_evidence
    from mncs_fabric.io import load_json
    from mncs_fabric.service import FabricService
    from mncs_fabric.resources import PlacementRequest, ResourceSnapshot, evaluate_placement, validate_placement_observation
    from mncs_fabric.collections import build_execution_collection, build_work_item, validate_execution_collection
    from mncs_fabric.worker import LocalWorker
    from mncs_fabric.worker_state import validate_worker_description
    from mncs_fabric.runtime import build_runtime_capability_observation, build_runtime_environment, build_runtime_observation, build_runtime_profile, validate_runtime_capability_observation, validate_runtime_observation
    service = FabricService()
    public_contract = build_public_contract(__import__("mncs_fabric").__version__)
    validate_public_contract(public_contract)
    if public_contract["features"]["native_bundle_transfer"] is not True:
        return "FAIL", "public contract does not advertise implemented native bundle transfer", []
    if public_contract["features"]["resource_observation"] is not True or public_contract["features"]["placement_request"] is not True:
        return "FAIL", "public contract does not advertise resource placement support", []
    if public_contract["features"].get("runtime_capability_evidence") is not True or public_contract["features"].get("sequential_cpu_offload_evidence") is not True:
        return "FAIL", "public contract does not advertise the physically evidenced runtime capability path", []
    if not all(public_contract["features"].get(feature) is True for feature in ("remote_worker_description", "remote_resource_refresh", "worker_liveness", "execution_collections")):
        return "FAIL", "public contract does not advertise worker-state and collection support", []
    snapshot = ResourceSnapshot(worker_identity="forge-resource", captured_at="2099-01-01T00:00:00Z", host_memory_total_bytes=8 * 1024**3, host_memory_available_bytes=4 * 1024**3, cpu_logical_count=2, architecture="fixture", accelerators=(), observation_source="forge-fixture").to_dict()
    admission = evaluate_placement(PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=1024), snapshot)
    if admission["disposition"] != "PASS":
        return "FAIL", "resource placement fixture did not admit bounded CPU execution", [{"admission": admission}]
    gpu_snapshot = ResourceSnapshot(worker_identity="forge-gpu", captured_at="2099-01-01T00:00:00Z", host_memory_total_bytes=16 * 1024**3, host_memory_available_bytes=8 * 1024**3, cpu_logical_count=4, architecture="fixture", accelerators=({"index": 0, "vendor": "nvidia", "backend": "cuda", "device_name": "forge-gpu", "hardware_identity": "sha256:" + "a" * 64, "total_memory_bytes": 8 * 1024**3, "free_memory_bytes": 7 * 1024**3, "driver_version": "fixture", "runtime_version": "fixture", "execution_probe": "UNKNOWN", "precision_probes": {}, "observation_source": "forge-fixture"},), observation_source="forge-fixture").to_dict()
    runtime_profile = build_runtime_profile("forge-gpu", captured_at="2099-01-01T00:00:00Z")
    runtime_observation = build_runtime_observation(worker_identity="forge-gpu", runtime_profile=runtime_profile, probe={"accelerator_backend": "cuda", "execution_probe": "PASS", "precision_probes": {"float32": "PASS"}}, captured_at="2099-01-01T00:00:00Z")
    runtime_admission = evaluate_placement(PlacementRequest(execution_device="accelerator", accelerator_backend="cuda"), gpu_snapshot, runtime_observation=runtime_observation)
    if runtime_admission["disposition"] != "PASS" or runtime_admission.get("runtime_observation_identity") != runtime_observation["runtime_observation_identity"]:
        return "FAIL", "runtime-aware accelerator admission fixture did not bind the runtime observation", [{"admission": runtime_admission}]
    offload_profile = build_runtime_profile("forge-gpu", captured_at="2099-01-01T00:00:00Z")
    offload_environment = build_runtime_environment(runtime_profile=offload_profile, components={"torch": "fixture", "accelerate": "fixture"}, captured_at="2099-01-01T00:00:00Z")
    offload_capability = build_runtime_capability_observation(worker_identity="forge-gpu", runtime_profile=offload_profile, runtime_environment=offload_environment, capability="sequential-cpu-offload", status="PASS", evidence={"actual_mode": "sequential-cpu-offload", "mechanism": "fixture", "cuda_execution": "PASS", "offload_hook_count": 1}, captured_at="2099-01-01T00:00:00Z")
    offload_request = PlacementRequest(execution_device="accelerator", accelerator_backend="cuda", offload="sequential-cpu", model_storage_bytes=7 * 1024**3, minimum_host_memory_bytes=1024, minimum_accelerator_working_bytes=1024, runtime_supports_sequential_cpu_offload=True)
    offload_admission = evaluate_placement(offload_request, gpu_snapshot, runtime_observation=runtime_observation, runtime_capability_observation=offload_capability)
    if offload_admission["disposition"] != "PASS" or offload_admission.get("admission_mode") != "sequential-cpu-offload":
        return "FAIL", "runtime-capability offload admission fixture did not pass", [{"admission": offload_admission}]
    validate_runtime_capability_observation(offload_capability, expected_worker_id="forge-gpu", expected_environment_identity=offload_environment["runtime_environment_identity"])
    with tempfile.TemporaryDirectory(prefix="mncs-fabric-state-forge-") as directory:
        root = Path(directory)
        bundle_root = root / "bundle"
        bundle_root.mkdir()
        description = LocalWorker("forge-worker", bundle_root, root / "worker.jsonl").description()
        validate_worker_description(description, expected_worker_id="forge-worker")
        profile = build_runtime_profile("forge-worker", captured_at="2099-01-01T00:00:00Z")
        observation = build_runtime_observation(worker_identity="forge-worker", runtime_profile=profile, probe={"execution_probe": "UNKNOWN", "precision_probes": {}, "accelerator_backend": None}, captured_at="2099-01-01T00:00:00Z")
        validate_runtime_observation(observation, expected_worker_id="forge-worker")
        item = build_work_item(job_identity="sha256:" + "1" * 64)
        collection = build_execution_collection([item], [{"work_item_identity": item["work_item_identity"], "disposition": "PASS", "record_identity": "sha256:" + "2" * 64}])
        validate_execution_collection(collection)
    with tempfile.TemporaryDirectory(prefix="mncs-fabric-forge-") as directory:
        output = Path(directory)
        manifest = verify_manifest(ROOT / "examples/portable-python/bundle", load_json(ROOT / "examples/portable-python/artifact-manifest.json"))
        plan = service.validate_plan(load_json(ROOT / "examples/portable-python/job-plan.json"))
        record = service.execute_local(plan, ROOT / "examples/portable-python/bundle", manifest, "forge-local", results_dir=output / "results")
        if record["outcome"] != "PASS":
            return "FAIL", "portable example execution failed", [{"operation": "run", "outcome": record["outcome"]}]
        cohort = service.reconcile([record])
        if cohort["outcome"] != "PASS":
            return "FAIL", "portable example reconciliation failed", [{"operation": "reconcile", "outcome": cohort["outcome"]}]
    receipt_snapshot = json.loads((ROOT / "compat/mncs-execution-receipt-0.1.snapshot.json").read_text(encoding="utf-8"))
    bundle_snapshot = json.loads((ROOT / "compat/mncs-execution-bundle-0.1-experimental.snapshot.json").read_text(encoding="utf-8"))
    challenge_snapshot = json.loads((ROOT / "compat/mncs-execution-challenge-0.1-experimental.snapshot.json").read_text(encoding="utf-8"))
    if receipt_snapshot.get("unsupported_versions") != "fail-closed" or bundle_snapshot.get("unsupported_version_behavior") != "explicit UNKNOWN; never silently accepted" or challenge_snapshot.get("unsupported_version_behavior") != "explicit UNKNOWN; never silently accepted":
        return "FAIL", "compatibility snapshots are not fail-closed", []
    evidence_reports = []
    for evidence_path in (ROOT / "development-evidence/fedora-two-host-phase1.json", ROOT / "development-evidence/fedora-persistent-two-host.json", ROOT / "development-evidence/fedora-native-bundle-two-host.json", ROOT / "development-evidence/fedora-resource-placement.json", ROOT / "development-evidence/fedora-worker-state.json", ROOT / "development-evidence/windows-gpu-worker.json", ROOT / "development-evidence/fedora-windows-heterogeneous.json", ROOT / "development-evidence/windows-sequential-offload.json", ROOT / "development-evidence/three-node-heterogeneous.json", ROOT / "development-evidence/heterogeneous-fault-profiles.json", ROOT / "development-evidence/raspberry-pi-preflight.json"):
        if evidence_path.exists():
            evidence_report = validate_physical_evidence(json.loads(evidence_path.read_text(encoding="utf-8")))
            evidence_reports.append({"path": str(evidence_path.relative_to(ROOT)), "report": evidence_report})
            if evidence_report["outcome"] != "PASS":
                return "FAIL", "sanitized physical evidence failed validation", [{"operation": "physical-evidence-validation", "report": evidence_report, "path": str(evidence_path.relative_to(ROOT))}]
    return "PASS", "Fabric suite, public contract, consumer API, worker state/collections, runtime-profile/runtime-capability fixtures, native bundle transfer, receipt/bundle/challenge compatibility, TLS loopback, replay checks, resource observation/admission, and sanitized heterogeneous physical evidence validation passed", [{"operation": "fabric-validation", "tests": result.testsRun, "public_contract": public_contract["contract_identity"], "worker_state": "description, refresh, liveness, and collection fixtures covered", "runtime": "profile, environment, CUDA, and sequential-offload capability fixture boundaries covered", "resource_placement": "fixture-covered; physical Windows CUDA/offload evidence is validated offline when present", "tls": "covered by unittest", "challenge": "covered by unittest", "physical_evidence": evidence_reports}]


def main() -> int:
    line = sys.stdin.readline()
    request = json.loads(line)
    if request.get("type") == "capabilities":
        result = {"protocol_version": "0.1", "type": "capabilities", "request_id": request.get("request_id", "forge-capabilities"), "provider": PROVIDER, "analyses": ["inspection"], "statuses": ["PASS", "FAIL", "UNKNOWN"], "cancellation": False, "health_checks": False, "extensions": {"supported_constructs": SUPPORTED_CONSTRUCTS, "unsupported_constructs": ["real-second-host-network-evidence", "independent-certification"], "limitations": ["operator-controlled local development evidence", "accelerator discovery is not execution proof", "runtime capability evidence is not attestation"]}}
    elif request.get("type") == "analysis_request" and request.get("analysis") == "inspection":
        status, summary, witnesses = run_validation()
        result = response(request, status, summary, limitations=["Forge execution is development evidence, not independent certification."], witnesses=witnesses)
    else:
        result = response(request, "UNKNOWN", "unsupported Forge request", limitations=["only Provider Protocol 0.1 capabilities and inspection are supported"])
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
