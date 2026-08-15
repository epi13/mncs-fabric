from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.errors import ValidationError
from mncs_fabric.package_artifact import (
    describe_package_artifact,
    validate_package_artifact,
    verify_package_artifact,
    write_artifact_descriptor,
)
from mncs_fabric.protocol import make_envelope, validate_envelope
from mncs_fabric.transport import InProcessTransport
from mncs_fabric.worker import LocalWorker
from mncs_fabric.controller import LocalController


class PackageArtifactTests(unittest.TestCase):
    def test_describe_and_verify_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mncs-fabric-0.2.0a24.tar.gz"
            path.write_bytes(b"fabric-sdist-bytes")
            described = describe_package_artifact(path, version="0.2.0a24")
            checked = validate_package_artifact(described)
            self.assertTrue(checked["digest"].startswith("sha256:"))
            verify_package_artifact(path, checked)
            path.write_bytes(b"corrupted")
            with self.assertRaises(ValidationError):
                verify_package_artifact(path, checked)

    def test_wrong_version_and_malformed_descriptor_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pkg.tar.gz"
            path.write_bytes(b"abc")
            with self.assertRaises(ValidationError):
                describe_package_artifact(path, version="not-a-version")
            described = describe_package_artifact(path, version="0.2.0a24")
            tampered = dict(described)
            tampered["version"] = "0.2.0a1"
            with self.assertRaises(ValidationError):
                validate_package_artifact(tampered)

    def test_controller_transfers_artifact_over_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            source = root / "mncs-fabric-0.2.0a24.tar.gz"
            source.write_bytes(b"transfer-me" * 100)
            worker = LocalWorker("xfer-worker", bundle, root / "worker.jsonl")
            controller = LocalController("xfer-controller", root / "controller.jsonl")
            controller.register(worker)
            result = controller.transfer_package_artifact("xfer-worker", source, version="0.2.0a24")
            self.assertEqual(result["result"]["disposition"], "PASS")
            self.assertTrue(result["artifact"]["digest"].startswith("sha256:"))
            envelope = make_envelope(
                "worker.package-artifact.request",
                controller_id="xfer-controller",
                worker_id="xfer-worker",
                request_id="bad",
                job_id="package-artifact",
                nonce="n" * 16,
                payload={"artifact_request_identity": "sha256:" + "0" * 64, "mode": "commit"},
                created_at="2026-08-15T00:00:00Z",
                expires_at="2026-08-15T00:01:00Z",
            )
            transport = InProcessTransport(worker)
            with self.assertRaises(Exception):
                validate_envelope(transport.request(envelope))
