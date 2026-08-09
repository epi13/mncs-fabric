from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import ssl
import threading
import unittest

from mncs_fabric.api import ConsumerContext, FabricClient, RemoteWorkerConfig
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.bundle_transfer import BundleCache
from mncs_fabric.bundles import build_bundle_archive
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint
from mncs_fabric.errors import ProtocolError
from mncs_fabric.models import validate_job_plan
from mncs_fabric.transport import TLSWorkerServer
from mncs_fabric.worker import LocalWorker

from test_transport import _certificates


class BundleTransferTests(unittest.TestCase):
    def test_cache_rejects_reordered_chunk_and_publishes_atomically(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "task.py").write_text("print('bundle')\n", encoding="utf-8")
            archive = root / "bundle.zip"
            report = build_bundle_archive(source, archive)
            cache = BundleCache(root / "cache")
            transfer_id = "test-transfer"
            status = cache.begin(transfer_id=transfer_id, bundle_identity=report.bundle_identity, archive_identity=report.archive_identity, total_bytes=archive.stat().st_size, chunk_bytes=64, chunk_count=(archive.stat().st_size + 63) // 64)
            self.assertEqual(status, "TRANSFER_REQUIRED")
            with self.assertRaises(ProtocolError):
                cache.chunk(transfer_id=transfer_id, bundle_identity=report.bundle_identity, archive_identity=report.archive_identity, sequence=1, data=b"wrong")
            self.assertFalse((cache.bundle_root / report.bundle_identity).exists())

    @unittest.skipUnless(__import__("shutil").which("openssl"), "openssl is required")
    def test_public_remote_api_transfers_bundle_and_returns_receipt(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            source = root / "source"
            source.mkdir()
            (source / "task.py").write_text("from pathlib import Path\nPath('result.json').write_text('native-transfer')\n", encoding="utf-8")
            manifest = build_manifest(source)
            plan = validate_job_plan({"schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "bundle:public", "candidate_identity": "sha256:" + "f" * 64, "evaluator_identity": None, "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": ["python"], "result_paths": ["result.json"], "network_policy": "DECLARED_OFFLINE"})
            archive = root / "execution-bundle.zip"
            bundle = build_bundle_archive(source, archive)
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            server_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            client_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", "worker-bundle", server_fp)
            worker_trust.enroll("controller", "controller-bundle", client_fp)
            worker = LocalWorker("worker-bundle", root / "empty", root / "worker.jsonl", bundle_cache_root=root / "cache")
            server = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-bundle", worker_id="worker-bundle", trust_store=worker_trust, timeout=3)
            port = server.bind()
            thread = threading.Thread(target=server.serve_forever, kwargs={"max_requests": 8, "idle_timeout": 5}, daemon=True)
            thread.start()
            client = FabricClient("controller-bundle", root / "controller-api.jsonl")
            client.register_remote_worker(RemoteWorkerConfig("worker-bundle", "127.0.0.1", port, ("python",), cert["ca"], cert["client"], cert["client_key"], root / "controller-trust.jsonl", timeout=3))
            transferred = client.ensure_bundle("worker-bundle", archive, expected_bundle_identity=bundle.bundle_identity)
            self.assertEqual(transferred["status"], "COMMITTED")
            result = client.execute(plan, manifest, worker_id="worker-bundle", request_id="bundle-request", consumer_context=ConsumerContext("RAVEL", "sha256:" + "1" * 64))[0]
            self.assertEqual(result["disposition"], "EXECUTED")
            self.assertEqual(client.verify_receipt(result["receipt"])["outcome"], "PASS")
            self.assertEqual(result["provenance_binding"]["bundle_identity"], bundle.bundle_identity)
            duplicate = client.execute(plan, manifest, worker_id="worker-bundle", request_id="bundle-request", consumer_context=ConsumerContext("RAVEL", "sha256:" + "1" * 64))[0]
            self.assertEqual(duplicate["disposition"], "DUPLICATE_IDEMPOTENT")
            self.assertEqual(duplicate["bundle_identity"], bundle.bundle_identity)
            server.request_stop()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
