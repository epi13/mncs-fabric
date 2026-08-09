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

PROVIDER = {"id": "mncs-fabric-local", "name": "MNCS Fabric local validation", "identity": "mncs-fabric-local-v1", "version": "0.4"}
SUPPORTED_CONSTRUCTS = ["fabric-unit-suite", "fabric-compile", "portable-example", "receipt-compatibility", "execution-bundle-compatibility", "execution-challenge-compatibility", "bounded-protocol-framing", "tls-loopback", "enrollment-revocation", "replay-adversarial", "scheduler-reconciliation", "resource-observation", "placement-admission", "placement-evidence", "two-host-harness-static-validation", "two-host-evidence-validation", "persistent-worker-evidence", "public-contract-validation", "public-consumer-api", "consumer-provenance-binding", "native-bundle-transfer", "bundle-cache-integrity"]


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
    service = FabricService()
    public_contract = build_public_contract(__import__("mncs_fabric").__version__)
    validate_public_contract(public_contract)
    if public_contract["features"]["native_bundle_transfer"] is not True:
        return "FAIL", "public contract does not advertise implemented native bundle transfer", []
    if public_contract["features"]["resource_observation"] is not True or public_contract["features"]["placement_request"] is not True:
        return "FAIL", "public contract does not advertise resource placement support", []
    snapshot = ResourceSnapshot(worker_identity="forge-resource", captured_at="2099-01-01T00:00:00Z", host_memory_total_bytes=8 * 1024**3, host_memory_available_bytes=4 * 1024**3, cpu_logical_count=2, architecture="fixture", accelerators=(), observation_source="forge-fixture").to_dict()
    admission = evaluate_placement(PlacementRequest(execution_device="cpu", minimum_host_memory_bytes=1024), snapshot)
    if admission["disposition"] != "PASS":
        return "FAIL", "resource placement fixture did not admit bounded CPU execution", [{"admission": admission}]
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
    for evidence_path in (ROOT / "development-evidence/fedora-two-host-phase1.json", ROOT / "development-evidence/fedora-persistent-two-host.json", ROOT / "development-evidence/fedora-native-bundle-two-host.json", ROOT / "development-evidence/fedora-resource-placement.json"):
        if evidence_path.exists():
            evidence_report = validate_physical_evidence(json.loads(evidence_path.read_text(encoding="utf-8")))
            evidence_reports.append({"path": str(evidence_path.relative_to(ROOT)), "report": evidence_report})
            if evidence_report["outcome"] != "PASS":
                return "FAIL", "sanitized physical evidence failed validation", [{"operation": "physical-evidence-validation", "report": evidence_report, "path": str(evidence_path.relative_to(ROOT))}]
    return "PASS", "Fabric suite, public contract, consumer API, native bundle transfer, receipt/bundle/challenge compatibility, TLS loopback, replay checks, resource observation/admission, and sanitized physical evidence validation passed", [{"operation": "fabric-validation", "tests": result.testsRun, "public_contract": public_contract["contract_identity"], "resource_placement": "fixture-covered; accelerator execution remains optional", "tls": "covered by unittest", "challenge": "covered by unittest", "physical_evidence": evidence_reports}]


def main() -> int:
    line = sys.stdin.readline()
    request = json.loads(line)
    if request.get("type") == "capabilities":
        result = {"protocol_version": "0.1", "type": "capabilities", "request_id": request.get("request_id", "forge-capabilities"), "provider": PROVIDER, "analyses": ["inspection"], "statuses": ["PASS", "FAIL", "UNKNOWN"], "cancellation": False, "health_checks": False, "extensions": {"supported_constructs": SUPPORTED_CONSTRUCTS, "unsupported_constructs": ["physical-cuda-evidence", "sequential-offload-evidence", "real-second-host-network-evidence", "independent-certification"], "limitations": ["operator-controlled local development evidence", "accelerator discovery is not execution proof"]}}
    elif request.get("type") == "analysis_request" and request.get("analysis") == "inspection":
        status, summary, witnesses = run_validation()
        result = response(request, status, summary, limitations=["Forge execution is development evidence, not independent certification."], witnesses=witnesses)
    else:
        result = response(request, "UNKNOWN", "unsupported Forge request", limitations=["only Provider Protocol 0.1 capabilities and inspection are supported"])
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
