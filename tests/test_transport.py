from __future__ import annotations

import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
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
