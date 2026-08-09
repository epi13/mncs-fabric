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
sys.path.insert(0, str(ROOT / "src"))

PROVIDER = {"id": "mncs-fabric-local", "name": "MNCS Fabric local validation", "identity": "mncs-fabric-local-v1", "version": "0.3"}


def response(request: dict[str, object], status: str, summary: str, *, limitations: list[str] | None = None, witnesses: list[object] | None = None) -> dict[str, object]:
    return {"protocol_version": "0.1", "type": "analysis_response", "request_id": request.get("request_id", "forge-local"), "provider": PROVIDER, "status": status, "summary": summary, "witnesses": witnesses or [], "limitations": limitations or [], "extensions": {"unsupported": [], "mncs_forge": {"assumptions": ["validation is operator-controlled development evidence"], "dependency_envelope": {"paths": ["src", "tests", "schemas"], "identities": {}, "complete": False}}}}


def run_validation() -> tuple[str, str, list[object]]:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        result_stream = io.StringIO()
        result = unittest.TextTestRunner(stream=result_stream, verbosity=0).run(suite)
    if not result.wasSuccessful():
        return "FAIL", "Fabric unit/integration suite failed", [{"failures": len(result.failures), "errors": len(result.errors)}]
    import compileall
    if not compileall.compile_dir(str(ROOT / "src"), quiet=1):
        return "FAIL", "Fabric source compilation failed", []
    from mncs_fabric.artifacts import verify_manifest
    from mncs_fabric.io import load_json
    from mncs_fabric.service import FabricService
    service = FabricService()
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
    if receipt_snapshot.get("unsupported_versions") != "fail-closed" or bundle_snapshot.get("unsupported_version_behavior") != "explicit UNKNOWN; never silently accepted":
        return "FAIL", "compatibility snapshots are not fail-closed", []
    return "PASS", "Fabric suite, compilation, portable example, receipt compatibility, bundle compatibility, TLS loopback, and replay checks passed", [{"operation": "fabric-validation", "tests": result.testsRun, "tls": "covered by unittest"}]


def main() -> int:
    line = sys.stdin.readline()
    request = json.loads(line)
    if request.get("type") == "capabilities":
        result = {"protocol_version": "0.1", "type": "capabilities", "request_id": request.get("request_id", "forge-capabilities"), "provider": PROVIDER, "analyses": ["inspection"], "statuses": ["PASS", "FAIL", "UNKNOWN"], "cancellation": False, "health_checks": False, "extensions": {"supported_constructs": ["fabric-unit-suite", "fabric-compile", "portable-example", "receipt-compatibility", "execution-bundle-compatibility", "bounded-protocol-framing", "tls-loopback", "enrollment-revocation", "replay-adversarial", "scheduler-reconciliation"], "unsupported_constructs": ["real-second-host-network-evidence", "bulk-cross-host-bundle-transfer", "independent-certification"], "limitations": ["operator-controlled local development evidence"]}}
    elif request.get("type") == "analysis_request" and request.get("analysis") == "inspection":
        status, summary, witnesses = run_validation()
        result = response(request, status, summary, limitations=["Forge execution is development evidence, not independent certification."], witnesses=witnesses)
    else:
        result = response(request, "UNKNOWN", "unsupported Forge request", limitations=["only Provider Protocol 0.1 capabilities and inspection are supported"])
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
