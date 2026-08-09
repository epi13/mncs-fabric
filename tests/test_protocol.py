import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.auth import KeyRecord, Keyring
from mncs_fabric.canonical import attach_identity, sha256_identity
from mncs_fabric.controller import LocalController
from mncs_fabric.errors import ProtocolError
from mncs_fabric.models import validate_job_plan
from mncs_fabric.protocol import make_envelope, validate_envelope
from mncs_fabric.worker import LocalWorker


def identity(char: str) -> str:
    return "sha256:" + char * 64


def dispatch_values(root: Path):
    manifest = build_manifest(root)
    plan = validate_job_plan({
        "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "protocol:job",
        "candidate_identity": identity("a"), "evaluator_identity": None,
        "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"],
        "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096,
        "environment": {}, "required_capabilities": ["python"], "result_paths": [], "network_policy": "UNSPECIFIED",
    })
    return plan, manifest


class ProtocolTests(unittest.TestCase):
    def test_authentication_and_tamper_rejection(self):
        keyring = Keyring({"k1": KeyRecord("k1", b"operator-secret")})
        envelope = make_envelope("status.request", controller_id="c", worker_id="w", request_id="r", job_id="j", nonce="nonce-1234567890", payload={"job_identity": identity("a")}, created_at="2026-01-01T00:00:00Z", expires_at="2026-01-01T00:01:00Z", keyring=keyring, key_id="k1")
        self.assertEqual(validate_envelope(envelope, keyring=keyring, require_authentication=True), envelope)
        tampered = copy.deepcopy(envelope)
        tampered["payload"]["job_identity"] = identity("b")
        with self.assertRaises(ProtocolError):
            validate_envelope(tampered, keyring=keyring, require_authentication=True)
        with self.assertRaises(ProtocolError):
            validate_envelope(envelope, keyring=Keyring({"other": KeyRecord("other", b"bad")}), require_authentication=True)

        future = copy.deepcopy(envelope)
        future["protocol_version"] = "mncs-fabric.protocol.v99"
        with self.assertRaises(ProtocolError):
            validate_envelope(future, keyring=keyring, require_authentication=True)

    def test_stale_unknown_version_wrong_worker_and_duplicate_dispatch(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "bundle"
        root.mkdir()
        (root / "task.py").write_text("print('ok')", encoding="utf-8")
        plan, manifest = dispatch_values(root)
        worker = LocalWorker("worker-a", root, Path(temporary.name) / "worker.jsonl")
        envelope = make_envelope("dispatch.request", controller_id="controller", worker_id="worker-a", request_id="request-1", job_id=plan["job_id"], nonce="dispatch-123456789", payload={"job_plan": plan, "artifact_manifest": manifest, "request_identity": sha256_identity({"job_plan": plan, "artifact_manifest": manifest})}, created_at="2026-01-01T00:00:00Z", expires_at="2026-01-01T00:01:00Z")
        first = worker.handle(envelope, now="2026-01-01T00:00:10Z")
        second = worker.handle(envelope, now="2026-01-01T00:00:10Z")
        self.assertEqual(first["message_type"], "execution.result")
        self.assertEqual(second["payload"]["disposition"], "DUPLICATE_IDEMPOTENT")
        changed = copy.deepcopy(envelope)
        changed["payload"]["job_plan"]["candidate_identity"] = identity("b")
        changed["payload"]["job_plan"] = validate_job_plan(changed["payload"]["job_plan"])
        changed["payload"]["request_identity"] = sha256_identity({"job_plan": changed["payload"]["job_plan"], "artifact_manifest": manifest})
        changed["message_id"] = sha256_identity({key: value for key, value in changed.items() if key != "message_id"})
        with self.assertRaises(ProtocolError):
            worker.handle({**envelope, "worker_id": "worker-b"})
        replay = worker.handle(changed, now="2026-01-01T00:00:10Z")
        self.assertEqual(replay["payload"]["disposition"], "CONFLICTING_REPLAY")
        with self.assertRaises(ProtocolError):
            validate_envelope(envelope, now="2026-01-01T00:02:00Z")

    def test_controller_worker_in_process_replication(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "bundle"
        root.mkdir()
        (root / "task.py").write_text("print('ok')", encoding="utf-8")
        plan, manifest = dispatch_values(root)
        controller = LocalController("controller", Path(temporary.name) / "controller.jsonl")
        controller.register(LocalWorker("worker-b", root, Path(temporary.name) / "b.jsonl"))
        controller.register(LocalWorker("worker-a", root, Path(temporary.name) / "a.jsonl"))
        responses = controller.dispatch(plan, manifest, replicas=2)
        self.assertEqual([item["worker_id"] for item in responses], ["worker-a", "worker-b"])
        self.assertTrue(all(item["message_type"] == "execution.result" for item in responses))
        forged = copy.deepcopy(responses[0])
        forged_record = copy.deepcopy(forged["payload"]["record"])
        forged_record["candidate_identity"] = identity("f")
        forged_record = attach_identity(forged_record, "record_id")
        forged["payload"]["record"] = forged_record
        forged["payload"]["result_identity"] = forged_record["record_id"]
        forged["message_id"] = sha256_identity({key: value for key, value in forged.items() if key != "message_id"})
        with self.assertRaises(ProtocolError):
            controller.verify_response(forged, worker_id="worker-a", job_identity=plan["job_identity"], candidate_identity=plan["candidate_identity"], artifact_manifest_identity=plan["artifact_manifest_identity"])
