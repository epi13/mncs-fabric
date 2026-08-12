from __future__ import annotations

import ssl
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint
from mncs_fabric.errors import ProtocolError
from mncs_fabric.models import validate_job_plan
from mncs_fabric.api import FabricClient
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.registry import RegistryWorker, WorkerRegistry
from mncs_fabric.rendezvous import RendezvousCoordinator
from mncs_fabric.transport import TLSRendezvousServer, TLSRendezvousWorker
from mncs_fabric.worker import LocalWorker



def _certificates(root: Path) -> dict[str, Path]:
    openssl = shutil.which("openssl")
    assert openssl
    ca_key, ca_cert = root / "ca.key", root / "ca.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=Fabric test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result: dict[str, Path] = {"ca": ca_cert}
    for name in ("server", "client"):
        key, csr, cert = root / f"{name}.key", root / f"{name}.csr", root / f"{name}.pem"
        subprocess.run([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN=Fabric {name}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-sha256"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result[name] = cert
        result[f"{name}_key"] = key
    return result


class RendezvousTests(unittest.TestCase):
    def test_controller_service_exposes_live_rendezvous_fleet_to_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            source = root / "worker-root"
            source.mkdir()
            worker = LocalWorker("worker-service-rendezvous", source, root / "worker.jsonl")
            controller_trust_path = root / "controller-trust.jsonl"
            worker_trust_path = root / "worker-trust.jsonl"
            controller_trust = TrustStore(controller_trust_path)
            worker_trust = TrustStore(worker_trust_path)
            controller_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            worker_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", worker.worker_id, worker_fp)
            worker_trust.enroll("controller", "controller-service-rendezvous", controller_fp)
            registry_path = root / "workers.json"
            WorkerRegistry(registry_path, "controller-service-rendezvous").register(RegistryWorker(worker_id=worker.worker_id, host="127.0.0.1", port=6553, capabilities=("python",), ca_file=str(cert["ca"]), client_certificate=str(cert["server"]), client_key=str(cert["server_key"]), trust_state=str(controller_trust_path)))
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                rendezvous_port = int(probe.getsockname()[1])
            config = ControllerConfig("controller-service-rendezvous", root / "lifecycle.jsonl", socket_path=root / "consumer.sock", admin_socket_path=root / "admin.sock", service_log=root / "service.jsonl", worker_registry_path=registry_path, worker_state_path=root / "worker-state.jsonl", rendezvous_host="127.0.0.1", rendezvous_port=rendezvous_port, rendezvous_ca=cert["ca"], rendezvous_certificate=cert["server"], rendezvous_key=cert["server_key"], rendezvous_trust_state=controller_trust_path)
            service = ControllerService(config)
            service_thread = threading.Thread(target=service.run, kwargs={"max_seconds": 8}, daemon=True)
            service_thread.start()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not service.rendezvous_ready:
                time.sleep(0.02)
            self.assertTrue(service.rendezvous_ready)
            client = TLSRendezvousWorker(worker, "127.0.0.1", rendezvous_port, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], controller_id="controller-service-rendezvous", worker_id=worker.worker_id, trust_store=worker_trust, heartbeat_seconds=0.5, timeout=2)
            worker_thread = threading.Thread(target=client.run, kwargs={"max_seconds": 3}, daemon=True)
            worker_thread.start()
            consumer = FabricClient.connect(config.socket_path_value, client_identity="test-consumer")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                status = consumer.controller_status()
                if status["fleet"]["workers"] and status["fleet"]["workers"][0].get("availability") == "AVAILABLE":
                    break
                time.sleep(0.05)
            self.assertTrue(status["service_features"]["worker_rendezvous"], client.last_error)
            diagnostic = f"client={client.last_error}; server={service._rendezvous_server.last_error if service._rendezvous_server is not None else None}"
            self.assertTrue(status["fleet"]["workers"], diagnostic)
            self.assertEqual(status["fleet"]["workers"][0]["worker_id"], worker.worker_id)
            self.assertEqual(consumer.fleet()[0]["availability"], "AVAILABLE")
            consumer.close()
            worker_thread.join(timeout=5)
            service.request_stop()
            service_thread.join(timeout=5)
            self.assertFalse(worker_thread.is_alive())

    def test_worker_dials_controller_heartbeats_and_executes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = _certificates(root)
            source = root / "worker-root"
            source.mkdir()
            (source / "task.py").write_text("print('rendezvous-ok')\n", encoding="utf-8")
            manifest = build_manifest(source)
            plan = validate_job_plan({
                "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "rendezvous:job",
                "candidate_identity": manifest["manifest_identity"], "evaluator_identity": None,
                "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"],
                "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096,
                "environment": {}, "required_capabilities": ["python"], "result_paths": [],
                "network_policy": "DECLARED_OFFLINE",
            })
            controller_trust = TrustStore(root / "controller-trust.jsonl")
            worker_trust = TrustStore(root / "worker-trust.jsonl")
            controller_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii")))
            worker_fp = certificate_fingerprint(ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii")))
            controller_trust.enroll("worker", "worker-rendezvous", worker_fp)
            worker_trust.enroll("controller", "controller-rendezvous", controller_fp)
            worker = LocalWorker("worker-rendezvous", source, root / "worker.jsonl")
            coordinator = RendezvousCoordinator("controller-rendezvous", root / "rendezvous.jsonl", known_workers={"worker-rendezvous": {"concurrency_limit": 1}}, heartbeat_seconds=0.5, command_timeout=10)
            server = TLSRendezvousServer("127.0.0.1", 0, ca_file=cert["ca"], server_cert=cert["server"], server_key=cert["server_key"], controller_id="controller-rendezvous", trust_store=controller_trust, on_open=coordinator.open, on_message=coordinator.message, on_close=coordinator.close, timeout=2)
            port = server.bind()
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            client = TLSRendezvousWorker(worker, "127.0.0.1", port, ca_file=cert["ca"], client_cert=cert["client"], client_key=cert["client_key"], controller_id="controller-rendezvous", worker_id="worker-rendezvous", trust_store=worker_trust, heartbeat_seconds=0.5, timeout=2)
            worker_thread = threading.Thread(target=client.run, kwargs={"max_seconds": 3}, daemon=True)
            worker_thread.start()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not coordinator.states()[0].get("available"):
                time.sleep(0.05)
            self.assertEqual(coordinator.states()[0]["availability"], "AVAILABLE")
            results = coordinator.dispatch(plan, manifest, worker_id="worker-rendezvous")
            self.assertEqual(results[0]["disposition"], "EXECUTED")
            self.assertEqual(results[0]["record"]["outcome"], "PASS")
            scheduled = coordinator.dispatch(plan, manifest, request_id="scheduler-rendezvous-job")
            self.assertEqual(scheduled[0]["disposition"], "EXECUTED")
            self.assertEqual(scheduled[0]["worker_identity"], "worker-rendezvous")
            worker_thread.join(timeout=5)
            server.close()
            server_thread.join(timeout=2)
            self.assertFalse(worker_thread.is_alive())
            self.assertEqual(coordinator.states()[0]["availability"], "UNAVAILABLE")
            self.assertTrue((root / "rendezvous.jsonl").read_text(encoding="utf-8"))

    def test_duplicate_identity_and_disconnect_are_not_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "worker-root"
            source.mkdir()
            worker = LocalWorker("worker", source, root / "worker.jsonl")
            coordinator = RendezvousCoordinator("controller", root / "rendezvous.jsonl", known_workers={"worker": {}}, heartbeat_seconds=1)
            opening = {"request_id": "open", "payload": {"description": worker.description()}}
            accepted = coordinator.open("worker", "sha256:" + "a" * 64, opening)
            with self.assertRaises(ProtocolError):
                coordinator.open("worker", "sha256:" + "a" * 64, opening)
            coordinator.close(accepted["payload"]["session_id"])
            reconnected = coordinator.open("worker", "sha256:" + "a" * 64, opening)
            self.assertEqual(reconnected["payload"]["generation"], 2)
            coordinator.close(reconnected["payload"]["session_id"])
            self.assertEqual(coordinator.states()[0]["availability"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
