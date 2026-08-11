from __future__ import annotations

import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.controller import NetworkController
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint
from mncs_fabric.errors import ProtocolError
from mncs_fabric.models import validate_job_plan
from mncs_fabric.transport import TLSNetworkTransport, TLSWorkerServer, receive_frame
from mncs_fabric.worker import LocalWorker


OPENSSL = shutil.which("openssl")


def _certificates(root: Path) -> dict[str, Path]:
    assert OPENSSL
    ca_key, ca_cert = root / "ca.key", root / "ca.pem"
    subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=Fabric test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result: dict[str, Path] = {"ca": ca_cert}
    for name in ("server", "client"):
        key, csr, cert = root / f"{name}.key", root / f"{name}.csr", root / f"{name}.pem"
        subprocess.run([OPENSSL, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN=Fabric {name}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([OPENSSL, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-sha256"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result[name] = cert
        result[f"{name}_key"] = key
    return result


@unittest.skipUnless(OPENSSL, "openssl is required for ephemeral TLS integration certificates")
class TLSTransportTests(unittest.TestCase):
    def test_execution_response_uses_validated_job_bound_not_control_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text(
                "import time\ntime.sleep(0.6)\nprint('slow-network-ok')\n", encoding="utf-8"
            )
            manifest = build_manifest(bundle)
            plan = validate_job_plan(
                {
                    "schema_version": "mncs-fabric.job-plan.v0.1",
                    "job_id": "network:slow-bounded",
                    "candidate_identity": "sha256:" + "a" * 64,
                    "evaluator_identity": None,
                    "artifact_manifest_identity": manifest["manifest_identity"],
                    "argv": ["@python", "task.py"],
                    "working_directory": ".",
                    "timeout_seconds": 2,
                    "output_limit_bytes": 4096,
                    "environment": {},
                    "required_capabilities": ["python"],
                    "result_paths": [],
                    "network_policy": "DECLARED_OFFLINE",
                }
            )
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            controller_trust.enroll(
                "worker",
                "worker-slow",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii"))
                ),
            )
            worker_trust.enroll(
                "controller",
                "controller-slow",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii"))
                ),
            )
            worker = LocalWorker("worker-slow", bundle, root / "worker-ledger.jsonl")
            server = TLSWorkerServer(
                worker,
                "127.0.0.1",
                0,
                ca_file=cert["ca"],
                server_cert=cert["server"],
                server_key=cert["server_key"],
                controller_id="controller-slow",
                worker_id="worker-slow",
                trust_store=worker_trust,
                timeout=0.2,
            )
            port = server.bind()
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            transport = TLSNetworkTransport(
                "127.0.0.1",
                port,
                ca_file=cert["ca"],
                client_cert=cert["client"],
                client_key=cert["client_key"],
                expected_worker_id="worker-slow",
                trust_store=controller_trust,
                timeout=0.2,
                execution_timeout_overhead=0.5,
            )
            response = NetworkController(
                "controller-slow", root / "controller-ledger.jsonl"
            ).dispatch_via(
                transport,
                plan,
                manifest,
                worker_id="worker-slow",
                request_id="network-slow-1",
            )
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(response["payload"]["record"]["outcome"], "PASS")

    def test_job_timeout_remains_explicit_and_bounded_over_tls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text(
                "import time\ntime.sleep(2)\n", encoding="utf-8"
            )
            manifest = build_manifest(bundle)
            plan = validate_job_plan(
                {
                    "schema_version": "mncs-fabric.job-plan.v0.1",
                    "job_id": "network:job-timeout",
                    "candidate_identity": "sha256:" + "b" * 64,
                    "evaluator_identity": None,
                    "artifact_manifest_identity": manifest["manifest_identity"],
                    "argv": ["@python", "task.py"],
                    "working_directory": ".",
                    "timeout_seconds": 0.2,
                    "output_limit_bytes": 4096,
                    "environment": {},
                    "required_capabilities": ["python"],
                    "result_paths": [],
                    "network_policy": "DECLARED_OFFLINE",
                }
            )
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            controller_trust.enroll(
                "worker",
                "worker-job-timeout",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii"))
                ),
            )
            worker_trust.enroll(
                "controller",
                "controller-job-timeout",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii"))
                ),
            )
            worker = LocalWorker(
                "worker-job-timeout", bundle, root / "worker-ledger.jsonl"
            )
            server = TLSWorkerServer(
                worker,
                "127.0.0.1",
                0,
                ca_file=cert["ca"],
                server_cert=cert["server"],
                server_key=cert["server_key"],
                controller_id="controller-job-timeout",
                worker_id="worker-job-timeout",
                trust_store=worker_trust,
                timeout=0.2,
            )
            port = server.bind()
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            transport = TLSNetworkTransport(
                "127.0.0.1",
                port,
                ca_file=cert["ca"],
                client_cert=cert["client"],
                client_key=cert["client_key"],
                expected_worker_id="worker-job-timeout",
                trust_store=controller_trust,
                timeout=0.2,
                execution_timeout_overhead=1,
            )
            started = time.monotonic()
            response = NetworkController(
                "controller-job-timeout", root / "controller-ledger.jsonl"
            ).dispatch_via(
                transport,
                plan,
                manifest,
                worker_id="worker-job-timeout",
                request_id="network-job-timeout-1",
            )
            elapsed = time.monotonic() - started
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            record = response["payload"]["record"]
            self.assertEqual(record["outcome"], "UNKNOWN")
            self.assertEqual(record["termination_reason"], "TIMEOUT")
            self.assertLess(elapsed, 1.5)

    def test_mutually_authenticated_loopback_dispatch_and_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('network-ok')\n", encoding="utf-8")
            manifest = build_manifest(bundle)
            plan = validate_job_plan({"schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "network:job", "candidate_identity": "sha256:" + "a" * 64, "evaluator_identity": None, "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": ["python"], "result_paths": [], "network_policy": "DECLARED_OFFLINE"})
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            server_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            client_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", "worker-a", server_fp)
            worker_trust.enroll("controller", "controller-a", client_fp)
            worker = LocalWorker("worker-a", bundle, root / "worker-ledger.jsonl")
            server = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-a", worker_id="worker-a", trust_store=worker_trust)
            port = server.bind()
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            transport = TLSNetworkTransport("127.0.0.1", port, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], expected_worker_id="worker-a", trust_store=controller_trust)
            controller = NetworkController("controller-a", root / "controller-ledger.jsonl")
            controller.register_remote("worker-a", worker.capabilities(), transport)
            responses = controller.dispatch_remote(plan, manifest)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(responses[0]["message_type"], "execution.result")
            self.assertEqual(controller.reconcile_dispatch(responses)["outcome"], "PASS")
            self.assertEqual(controller.reconcile_dispatch(responses + [{"disposition": "UNKNOWN"}])["outcome"], "UNKNOWN")

            # The server requires a client certificate; a CA-trusted socket
            # without one is rejected during TLS negotiation.
            server3 = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-a", worker_id="worker-a", trust_store=worker_trust)
            port3 = server3.bind()
            thread3 = threading.Thread(target=server3.serve_once, daemon=True)
            thread3.start()
            no_client = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cert["ca"]))
            no_client.check_hostname = False
            with socket.create_connection(("127.0.0.1", port3), timeout=5) as raw:
                try:
                    with no_client.wrap_socket(raw, server_hostname="127.0.0.1"):
                        pass
                except ssl.SSLError:
                    pass
            thread3.join(timeout=5)
            self.assertFalse(thread3.is_alive())
            self.assertTrue(server3.last_error)

            # Revocation is checked before any dispatch is accepted.
            controller_trust.revoke("worker", "worker-a", reason="test-revocation")
            server2 = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-a", worker_id="worker-a", trust_store=worker_trust)
            port2 = server2.bind()
            thread2 = threading.Thread(target=server2.serve_once, daemon=True)
            thread2.start()
            revoked_transport = TLSNetworkTransport("127.0.0.1", port2, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], expected_worker_id="worker-a", trust_store=controller_trust)
            with self.assertRaises(ProtocolError):
                controller.dispatch_via(revoked_transport, plan, manifest, worker_id="worker-a", request_id="network:revoked")
            thread2.join(timeout=5)

    def test_frame_truncation_oversize_and_noncanonical_json_fail_closed(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.sendall(struct.pack(">I", 10) + b"{}")
        right.shutdown(socket.SHUT_WR)
        with self.assertRaises(ProtocolError):
            receive_frame(left)

        left2, right2 = socket.socketpair()
        self.addCleanup(left2.close)
        self.addCleanup(right2.close)
        right2.sendall(struct.pack(">I", 2 * 1024 * 1024 + 1))
        with self.assertRaises(ProtocolError):
            receive_frame(left2)

        left3, right3 = socket.socketpair()
        self.addCleanup(left3.close)
        self.addCleanup(right3.close)
        payload = b'{"b":1,"a":2}'
        right3.sendall(struct.pack(">I", len(payload)) + payload)
        with self.assertRaises(ProtocolError):
            receive_frame(left3)

    def test_bounded_persistent_service_handles_retries_without_rebinding_listener(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('persistent-ok')\n", encoding="utf-8")
            manifest = build_manifest(bundle)
            plan = validate_job_plan({"schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "persistent:job", "candidate_identity": "sha256:" + "a" * 64, "evaluator_identity": None, "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": ["python"], "result_paths": [], "network_policy": "DECLARED_OFFLINE"})
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            server_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            client_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", "worker-persistent", server_fp)
            worker_trust.enroll("controller", "controller-persistent", client_fp)
            worker = LocalWorker("worker-persistent", bundle, root / "worker-ledger.jsonl")
            server = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-persistent", worker_id="worker-persistent", trust_store=worker_trust, timeout=2)
            port = server.bind()
            thread = threading.Thread(target=server.serve_forever, kwargs={"max_requests": 5, "idle_timeout": 5}, daemon=True)
            thread.start()
            transport = TLSNetworkTransport("127.0.0.1", port, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], expected_worker_id="worker-persistent", trust_store=controller_trust, timeout=2)
            controller = NetworkController("controller-persistent", root / "controller-ledger.jsonl")
            controller.register_remote("worker-persistent", worker.capabilities(), transport)
            first = controller.dispatch_via(transport, plan, manifest, worker_id="worker-persistent", request_id="persistent-1")
            second = controller.dispatch_via(transport, plan, manifest, worker_id="worker-persistent", request_id="persistent-2")
            third = controller.dispatch_via(transport, plan, manifest, worker_id="worker-persistent", request_id="persistent-3")
            duplicate = controller.dispatch_via(transport, plan, manifest, worker_id="worker-persistent", request_id="persistent-3")
            changed = dict(plan)
            changed["candidate_identity"] = "sha256:" + "b" * 64
            changed = validate_job_plan(changed)
            conflicting = controller.dispatch_via(transport, changed, manifest, worker_id="worker-persistent", request_id="persistent-3")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual([item["message_type"] for item in (first, second, third)], ["execution.result"] * 3)
            self.assertEqual(duplicate["payload"]["disposition"], "DUPLICATE_IDEMPOTENT")
            self.assertEqual(conflicting["payload"]["disposition"], "CONFLICTING_REPLAY")
            self.assertEqual(server.handled_requests, 5)

    def test_persistent_service_reloads_revocation_between_requests_and_stops_idle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('revocation-ok')\n", encoding="utf-8")
            manifest = build_manifest(bundle)
            plan = validate_job_plan({"schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "persistent:revocation", "candidate_identity": "sha256:" + "c" * 64, "evaluator_identity": None, "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": ["python"], "result_paths": [], "network_policy": "DECLARED_OFFLINE"})
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            server_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            client_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", "worker-revocation", server_fp)
            worker_trust.enroll("controller", "controller-revocation", client_fp)
            worker = LocalWorker("worker-revocation", bundle, root / "worker-ledger.jsonl")
            server = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-revocation", worker_id="worker-revocation", trust_store=worker_trust, timeout=2)
            port = server.bind()
            thread = threading.Thread(target=server.serve_forever, kwargs={"max_requests": 2, "idle_timeout": 5}, daemon=True)
            thread.start()
            transport = TLSNetworkTransport("127.0.0.1", port, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], expected_worker_id="worker-revocation", trust_store=controller_trust, timeout=2)
            controller = NetworkController("controller-revocation", root / "controller-ledger.jsonl")
            first = controller.dispatch_via(transport, plan, manifest, worker_id="worker-revocation", request_id="revocation-1")
            self.assertEqual(first["message_type"], "execution.result")
            worker_trust.revoke("controller", "controller-revocation", reason="between-request-test")
            with self.assertRaises(ProtocolError):
                controller.dispatch_via(transport, plan, manifest, worker_id="worker-revocation", request_id="revocation-2")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(server.handled_requests, 1)

    def test_persistent_service_can_be_stopped_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "task.py").write_text("print('stop-ok')\n", encoding="utf-8")
            worker = LocalWorker("worker-stop", bundle, root / "worker-ledger.jsonl")
            trust = TrustStore(root / "trust.jsonl")
            server = TLSWorkerServer(worker, "127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-stop", worker_id="worker-stop", trust_store=trust)
            server.bind()
            thread = threading.Thread(target=server.serve_forever, kwargs={"idle_timeout": 30}, daemon=True)
            thread.start()
            server.request_stop()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
