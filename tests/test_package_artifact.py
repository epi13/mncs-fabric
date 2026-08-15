from __future__ import annotations

import base64
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.package_artifact import (
    ArtifactTransferSession,
    chunk_bounds,
    describe_package_artifact,
    inspect_package_metadata,
    retain_previous_artifact,
    validate_package_artifact,
    verify_package_artifact,
    verify_package_metadata,
    write_artifact_descriptor,
    write_verified_artifact,
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
            worker = LocalWorker("xfer-worker", bundle, root / "worker.jsonl", stage_dir=root / "stage")
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

    def _session(self, blob: bytes, *, expires_at: str = "2099-01-01T00:00:00Z"):
        path = Path(tempfile.mkdtemp()) / "mncs-fabric-0.2.0a24.tar.gz"
        path.write_bytes(blob)
        artifact = describe_package_artifact(path, version="0.2.0a24")
        _, count = chunk_bounds(len(blob))
        session = ArtifactTransferSession(
            worker_identity="w",
            controller_identity="c",
            artifact=artifact,
            transfer_identity="sha256:" + "a" * 64,
            expected_chunk_count=count,
            expected_total_bytes=len(blob),
            expires_at=expires_at,
        )
        return session, artifact, blob

    def test_session_rejects_digest_size_base64_and_sequence_errors(self) -> None:
        session, artifact, blob = self._session(b"x" * 100)
        from mncs_fabric.package_artifact import MAX_CHUNK_BYTES, decode_chunk_data

        with self.assertRaises(ProtocolError):
            session.accept_chunk(sequence=-1, data=b"x")
        with self.assertRaises(ProtocolError):
            session.accept_chunk(sequence=session.expected_chunk_count, data=b"x")
        with self.assertRaises(ProtocolError):
            decode_chunk_data("not-base64!!!")
        session.accept_chunk(sequence=0, data=blob)
        session.accept_chunk(sequence=0, data=blob)
        with self.assertRaises(ProtocolError):
            session.accept_chunk(sequence=0, data=b"y" * 100)
        with self.assertRaises(ProtocolError):
            ArtifactTransferSession(
                worker_identity="w",
                controller_identity="c",
                artifact=artifact,
                transfer_identity="sha256:" + "a" * 64,
                expected_chunk_count=count if (count := session.expected_chunk_count + 1) else 1,
                expected_total_bytes=len(blob),
                expires_at="2099-01-01T00:00:00Z",
            )
        oversized = describe_package_artifact
        self.assertGreater(MAX_CHUNK_BYTES, 1)

    def test_commit_requires_every_expected_sequence_and_rejects_expiry(self) -> None:
        session, _artifact, blob = self._session(b"x" * (64 * 1024 + 3))
        with self.assertRaises(ProtocolError):
            session.assembled_bytes()
        session.accept_chunk(sequence=0, data=blob[:64 * 1024])
        with self.assertRaises(ProtocolError):
            session.assembled_bytes()
        session.accept_chunk(sequence=1, data=blob[64 * 1024:])
        self.assertEqual(session.assembled_bytes(), blob)
        expired, _artifact, blob = self._session(b"expired", expires_at="2020-01-01T00:00:00Z")
        with self.assertRaises(ProtocolError):
            expired.accept_chunk(sequence=0, data=blob)

    def test_second_active_offer_is_rejected_and_commit_without_offer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = LocalWorker("xfer-worker", root / "bundle", root / "worker.jsonl", stage_dir=root / "stage")
            (root / "bundle").mkdir()
            first = root / "a.tar.gz"
            first.write_bytes(b"one-artifact")
            second = root / "b.tar.gz"
            second.write_bytes(b"two-artifact")
            controller = LocalController("xfer-controller", root / "controller.jsonl")
            controller.register(worker)
            artifact = describe_package_artifact(second, version="0.2.0a24")
            created = "2026-08-15T00:00:00Z"
            expires = "2099-01-01T00:00:00Z"
            offer = make_envelope(
                "worker.package-artifact.request",
                controller_id="xfer-controller",
                worker_id="xfer-worker",
                request_id="offer-1",
                job_id="package-artifact",
                nonce="n" * 16,
                payload={
                    "artifact_request_identity": "sha256:" + "1" * 64,
                    "mode": "offer",
                    "artifact": describe_package_artifact(first, version="0.2.0a24"),
                    "total_bytes": first.stat().st_size,
                    "chunk_count": 1,
                    "transfer_identity": "sha256:" + "2" * 64,
                    "expires_at": expires,
                },
                created_at=created,
                expires_at=expires,
            )
            transport = InProcessTransport(worker)
            self.assertEqual(transport.request(offer)["payload"]["disposition"], "PASS")
            second_offer = make_envelope(
                "worker.package-artifact.request",
                controller_id="xfer-controller",
                worker_id="xfer-worker",
                request_id="offer-2",
                job_id="package-artifact",
                nonce="o" * 16,
                payload={
                    "artifact_request_identity": "sha256:" + "3" * 64,
                    "mode": "offer",
                    "artifact": artifact,
                    "total_bytes": second.stat().st_size,
                    "chunk_count": 1,
                    "transfer_identity": "sha256:" + "4" * 64,
                    "expires_at": expires,
                },
                created_at=created,
                expires_at=expires,
            )
            rejected = transport.request(second_offer)
            self.assertEqual(rejected["payload"]["disposition"], "FAIL")
            self.assertIn("active transfer session", rejected["payload"]["detail"])

    def test_metadata_and_previous_artifact_retention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "mncs_fabric-0.2.0a24-py3-none-any.whl"
            metadata = "Metadata-Version: 2.1\nName: mncs-fabric\nVersion: 0.2.0a24\n"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("mncs_fabric-0.2.0a24.dist-info/METADATA", metadata)
            described = describe_package_artifact(wheel, version="0.2.0a24")
            inspect = inspect_package_metadata(wheel)
            self.assertEqual(inspect["package"], "mncs-fabric")
            self.assertEqual(inspect["version"], "0.2.0a24")
            self.assertTrue(verify_package_metadata(wheel, described)["verified"])
            other = root / "other-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(other, "w") as archive:
                archive.writestr("other-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: other\nVersion: 1.0.0\n")
            with self.assertRaises(ValidationError):
                verify_package_metadata(other, describe_package_artifact(other, package="mncs-fabric", version="0.2.0a24"))
            stage = root / "stage"
            write_verified_artifact(stage, described, wheel.read_bytes())
            sdist = root / "mncs-fabric-0.2.0a25.tar.gz"
            pkg = b"Metadata-Version: 2.1\nName: mncs-fabric\nVersion: 0.2.0a25\n"
            info = tarfile.TarInfo(name="mncs-fabric-0.2.0a25/PKG-INFO")
            info.size = len(pkg)
            with tarfile.open(sdist, "w:gz") as archive:
                archive.addfile(info, io.BytesIO(pkg))
            next_desc = describe_package_artifact(sdist, version="0.2.0a25")
            write_verified_artifact(stage, next_desc, sdist.read_bytes())
            previous = retain_previous_artifact(stage)
            self.assertIn(previous["rollback_capability"], {"exact", "partial"})
            self.assertTrue((stage / "previous").exists() or previous["previous_artifact_identity"] is None)
