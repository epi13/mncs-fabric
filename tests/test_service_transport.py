from __future__ import annotations

import base64
import os
import json
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.api import FabricAdminClient, FabricClient
from mncs_fabric.contracts import ConsumerContext
from mncs_fabric.bundles import build_bundle_archive
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.enrollment import TrustStore, certificate_fingerprint
from mncs_fabric.errors import ProtocolError
from mncs_fabric.lifecycle import LifecycleStore
from mncs_fabric.models import validate_job_plan
from mncs_fabric.registry import RegistryWorker, WorkerRegistry
from mncs_fabric.service_transport import SERVICE_MAX_FRAME_BYTES, SERVICE_REQUEST_SCHEMA, ServiceClientTransport
from mncs_fabric.transport import TLSWorkerServer
from mncs_fabric.targets import ExecutionTargetReference
from mncs_fabric.worker import LocalWorker
from mncs_fabric.canonical import attach_identity, sha256_identity
from tests.test_transport import _certificates


@unittest.skipUnless(os.name == "posix", "AF_UNIX persistent transport is currently POSIX-only")
class ServiceTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.config = ControllerConfig(
            "controller-service-test",
            root / "lifecycle.jsonl",
            heartbeat_seconds=0.5,
            service_log=root / "controller-service.jsonl",
            socket_path=root / "controller.sock",
            admin_socket_path=root / "controller-admin.sock",
        )
        self.service = ControllerService(self.config)
        self.thread = threading.Thread(target=self.service.run, kwargs={"max_seconds": 2.0}, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 2.0
        while not self.config.socket_path_value.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.config.socket_path_value.exists())
        self.assertEqual(self.service.status()["service_runtime"], "RUNNING")

    def tearDown(self) -> None:
        self.service.request_stop()
        self.thread.join(timeout=3.0)
        self.temp.cleanup()

    def test_consumer_and_admin_surfaces_are_distinct(self) -> None:
        consumer = FabricClient.connect(self.config.socket_path_value, client_identity="harness")
        self.assertEqual(consumer.controller_status()["controller_id"], "controller-service-test")
        self.assertEqual(consumer.fleet(), [])
        with self.assertRaises(ProtocolError):
            consumer.create_enrollment_authorization(ttl_seconds=60)
        with self.assertRaises(ProtocolError):
            consumer.enrollment_authorizations()
        with self.assertRaises(ProtocolError):
            consumer._service_transport.request("enrollment.approve", {"request_id": "missing"})  # type: ignore[union-attr]

        admin = FabricAdminClient.connect(self.config.admin_socket_path_value)
        authorization = admin.create_enrollment_authorization(ttl_seconds=60, metadata={"purpose": "test"})
        self.assertIn("token", authorization)
        self.assertNotIn("token", admin.enrollment_authorizations()[0])
        consumer.close()
        admin.close()

    def test_enrollment_submission_mutates_only_through_admin_surface(self) -> None:
        admin = FabricAdminClient.connect(self.config.admin_socket_path_value)
        authorization = admin.create_enrollment_authorization(
            ttl_seconds=60, expected_worker_identity="worker-admin-submit"
        )
        request = LifecycleStore.build_request(
            worker_identity="worker-admin-submit",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMDEyMzQ1Njc4OWFiY2RlZg==\n-----END PUBLIC KEY-----\n",
            hostname_hint="worker.example.test",
            operating_system="linux",
            architecture="x86_64",
            authorization_id=str(authorization["authorization_id"]),
        )
        submitted = admin.submit_enrollment(request, str(authorization["token"]))
        self.assertEqual(submitted["status"], "PENDING")
        self.assertEqual(admin.enrollment_pending()[0]["request_id"], request["request_id"])
        with self.assertRaises(ProtocolError):
            admin.submit_enrollment(request, str(authorization["token"]))
        admin.close()

    def test_client_disconnect_does_not_change_fleet_state_and_restart_reuses_it(self) -> None:
        admin = FabricAdminClient.connect(self.config.admin_socket_path_value)
        authorization = admin.create_enrollment_authorization(ttl_seconds=60)
        self.assertEqual(len(admin.enrollment_authorizations()), 1)
        admin.close()
        self.assertEqual(self.service.lifecycle.doctor()["outcome"], "PASS")
        self.service.request_stop()
        self.thread.join(timeout=3.0)
        restarted = ControllerService(self.config)
        self.assertEqual(restarted.status()["service_ledger"]["outcome"], "PASS")
        self.assertEqual(restarted.lifecycle.list_authorizations()[0]["status"], "ACTIVE")
        self.assertNotIn(str(authorization["token"]), self.config.service_log_path.read_text(encoding="utf-8"))

    def test_duplicate_service_request_is_rejected(self) -> None:
        transport = ServiceClientTransport(self.config.socket_path_value, client_identity="test-client")
        request_material = {
            "schema_version": SERVICE_REQUEST_SCHEMA,
            "client_identity": "test-client",
            "operation": "fleet.list",
            "arguments": {},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        request_id = attach_identity(request_material, "request_id")["request_id"]
        request = dict(request_material)
        request["request_id"] = request_id
        self.assertEqual(transport.request_envelope(request), {"workers": []})
        with self.assertRaises(ProtocolError):
            self.assertEqual(transport.request_envelope(request), {"workers": []})

    def test_consumer_bundle_upload_resumes_an_interrupted_transfer(self) -> None:
        root = Path(self.temp.name)
        source = root / "resume-source"
        source.mkdir()
        (source / "task.py").write_text("print('resume')\n", encoding="utf-8")
        archive = root / "consumer-resume.zip"
        report = build_bundle_archive(source, archive)
        self.assertIsNotNone(report.bundle_identity)
        self.assertIsNotNone(report.archive_identity)
        bundle_identity = str(report.bundle_identity)
        archive_identity = str(report.archive_identity)
        chunk_bytes = 32 * 1024
        total_bytes = archive.stat().st_size
        chunk_count = (total_bytes + chunk_bytes - 1) // chunk_bytes
        transfer_id = "service-" + sha256_identity(
            {
                "bundle_identity": bundle_identity,
                "archive_identity": archive_identity,
            }
        )[7:39]
        base = {
            "transfer_id": transfer_id,
            "bundle_identity": bundle_identity,
            "archive_identity": archive_identity,
            "total_bytes": total_bytes,
            "chunk_bytes": chunk_bytes,
            "chunk_count": chunk_count,
        }
        client = FabricClient.connect(self.config.socket_path_value, client_identity="resume-test")
        try:
            offered = client._service_transport.request("execution.bundle.begin", base)  # type: ignore[union-attr]
            self.assertEqual(offered["next_sequence"], 0)
            with archive.open("rb") as stream:
                first = stream.read(chunk_bytes)
            accepted = client._service_transport.request(  # type: ignore[union-attr]
                "execution.bundle.chunk",
                {
                    "transfer_id": transfer_id,
                    "bundle_identity": bundle_identity,
                    "archive_identity": archive_identity,
                    "sequence": 0,
                    "data": base64.b64encode(first).decode("ascii"),
                },
            )
            self.assertEqual(accepted["status"], "ACCEPTED")
            self.assertEqual(
                client._upload_service_bundle(archive),
                {
                    "bundle_identity": bundle_identity,
                    "archive_identity": archive_identity,
                },
            )
            content = self.service._consumer_bundle_cache.root_for(
                bundle_identity, archive_identity
            )
            self.assertTrue((content / "task.py").is_file())
        finally:
            client.close()

    def test_malformed_and_unsafe_socket_paths_fail_closed(self) -> None:
        root = Path(self.temp.name)
        bad_socket = root / "not-a-socket"
        bad_socket.write_text("do not replace", encoding="utf-8")
        bad_config = ControllerConfig("bad", root / "bad-lifecycle.jsonl", socket_path=bad_socket, admin_socket_path=root / "bad-admin.sock")
        with self.assertRaises(ProtocolError):
            ControllerService(bad_config).run(max_seconds=0.1)

        if os.name == "posix":
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o777)
            os.chmod(unsafe, 0o777)
            unsafe_config = ControllerConfig("unsafe", unsafe / "lifecycle.jsonl", socket_path=unsafe / "controller.sock", admin_socket_path=unsafe / "admin.sock")
            with self.assertRaises(ProtocolError):
                ControllerService(unsafe_config).run(max_seconds=0.1)
            target = root / "socket-target"
            target.write_text("do not replace", encoding="utf-8")
            linked = root / "linked.sock"
            linked.symlink_to(target)
            linked_config = ControllerConfig("linked", root / "linked-lifecycle.jsonl", socket_path=linked, admin_socket_path=root / "linked-admin.sock")
            with self.assertRaises(ProtocolError):
                ControllerService(linked_config).run(max_seconds=0.1)

    def test_only_one_controller_can_own_state(self) -> None:
        second = ControllerService(self.config)
        errors: list[Exception] = []

        def run_second() -> None:
            try:
                second.run(max_seconds=0.2)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=run_second)
        thread.start()
        time.sleep(0.1)
        thread.join(timeout=2.0)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ProtocolError)
        self.assertIn("already owned", str(errors[0]))

    def test_oversized_frame_is_closed_without_a_diagnostic_payload(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(1.0)
            stream.connect(str(self.config.socket_path_value))
            stream.sendall(struct.pack(">I", SERVICE_MAX_FRAME_BYTES + 1))
            self.assertEqual(stream.recv(1), b"")

    def test_controller_process_restart_reuses_the_same_durable_paths(self) -> None:
        self.service.request_stop()
        self.thread.join(timeout=3.0)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        command = [sys.executable, "-m", "mncs_fabric.cli", "controller", "service", "run", "--state", str(self.config.lifecycle_state), "--max-seconds", "0.15"]
        first = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
        second = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        status = subprocess.run([sys.executable, "-m", "mncs_fabric.cli", "controller", "status", "--state", str(self.config.lifecycle_state)], env=env, capture_output=True, text=True, check=False)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(json.loads(status.stdout)["service_ledger"]["outcome"], "PASS")
        self.assertEqual(json.loads(status.stdout)["service_runtime"], "STOPPED")

    def test_consumer_dispatches_through_controller_managed_worker_backend(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            cert_root = root / "certificates"
            cert_root.mkdir()
            cert = _certificates(cert_root)
            source = root / "source"
            source.mkdir()
            (source / "task.py").write_text("print('persistent-service-ok')\n", encoding="utf-8")
            manifest = build_manifest(source)
            plan = validate_job_plan(
                {
                    "schema_version": "mncs-fabric.job-plan.v0.1",
                    "job_id": "persistent-service:job",
                    "candidate_identity": manifest["manifest_identity"],
                    "evaluator_identity": None,
                    "artifact_manifest_identity": manifest["manifest_identity"],
                    "argv": ["@python", "task.py"],
                    "working_directory": ".",
                    "timeout_seconds": 5,
                    "output_limit_bytes": 4096,
                    "environment": {},
                    "required_capabilities": ["python"],
                    "result_paths": [],
                    "network_policy": "DECLARED_OFFLINE",
                }
            )

            controller_trust_path = root / "controller-trust.jsonl"
            worker_trust_path = root / "worker-trust.jsonl"
            controller_trust = TrustStore(controller_trust_path)
            worker_trust = TrustStore(worker_trust_path)
            controller_trust.enroll(
                "worker",
                "worker-service",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["server"].read_text(encoding="ascii"))
                ),
            )
            worker_trust.enroll(
                "controller",
                "controller-service",
                certificate_fingerprint(
                    ssl.PEM_cert_to_DER_cert(cert["client"].read_text(encoding="ascii"))
                ),
            )
            worker = LocalWorker(
                "worker-service",
                source,
                root / "worker-ledger.jsonl",
                bundle_cache_root=root / "worker-bundles",
            )
            worker_server = TLSWorkerServer(
                worker,
                "127.0.0.1",
                0,
                ca_file=cert["ca"],
                server_cert=cert["server"],
                server_key=cert["server_key"],
                controller_id="controller-service",
                worker_id="worker-service",
                trust_store=worker_trust,
                timeout=2,
            )
            port = worker_server.bind()
            worker_thread = threading.Thread(
                target=worker_server.serve_forever,
                kwargs={"max_requests": 20, "idle_timeout": 10},
                daemon=True,
            )
            worker_thread.start()

            registry = WorkerRegistry(root / "workers.json", controller_id="controller-service")
            registry.register(
                RegistryWorker(
                    worker_id="worker-service",
                    host="127.0.0.1",
                    port=port,
                    capabilities=tuple(sorted(worker.capabilities())),
                    ca_file=str(cert["ca"]),
                    client_certificate=str(cert["client"]),
                    client_key=str(cert["client_key"]),
                    trust_state=str(controller_trust_path),
                )
            )
            config = ControllerConfig(
                "controller-service",
                root / "lifecycle.jsonl",
                heartbeat_seconds=0.5,
                service_log=root / "controller-service.jsonl",
                socket_path=root / "controller.sock",
                admin_socket_path=root / "controller-admin.sock",
                worker_registry_path=root / "workers.json",
                worker_state_path=root / "controller-workers.jsonl",
                execution_bundle_root=root / "execution-bundles",
            )
            lifecycle = LifecycleStore(config.lifecycle_state)
            authorization = lifecycle.create_authorization(
                expected_worker_identity="worker-service"
            )
            enrollment_request = lifecycle.build_request(
                worker_identity="worker-service",
                public_key_pem="-----BEGIN PUBLIC KEY-----\nMDEyMzQ1Njc4OWFiY2RlZg==\n-----END PUBLIC KEY-----\n",
                hostname_hint="worker-service.local",
                operating_system="linux",
                architecture="x86_64",
                authorization_id=str(authorization["authorization_id"]),
            )
            lifecycle.submit_request(enrollment_request, str(authorization["token"]))
            lifecycle.approve_request(str(enrollment_request["request_id"]))
            archive = root / "consumer-owned-job.zip"
            bundle_report = build_bundle_archive(source, archive)
            service = ControllerService(config)
            service_thread = threading.Thread(
                target=service.run,
                kwargs={"max_seconds": 10.0},
                daemon=True,
            )
            service_thread.start()
            deadline = time.monotonic() + 3
            while not config.socket_path_value.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(config.socket_path_value.exists())

            client = FabricClient.connect(config.socket_path_value, client_identity="integration-test")
            try:
                status = client.controller_status()
                self.assertTrue(status["service_features"]["persistent_service_execution"])
                self.assertTrue(status["service_features"]["persistent_worker_observations"])
                self.assertTrue(status["service_features"]["target_aware_execution"])
                self.assertTrue(status["service_features"]["worker_commissioning"])
                self.assertTrue(status["service_features"]["worker_tool_capability_observations"])
                self.assertTrue(status["service_features"]["resumable_service_bundle_transfer"])
                self.assertFalse(status["service_features"]["rendezvous_membership_projection"])
                workers = client.workers()
                self.assertEqual(workers[0]["worker_id"], "worker-service")
                self.assertEqual(workers[0]["availability"], "AVAILABLE")
                observation = client.ingest_capability_observation(
                    "worker-service",
                    [
                        {
                            "kind": "runtime",
                            "namespace": "system",
                            "name": "python",
                            "attributes": {"status": "ready"},
                        },
                        {
                            "kind": "tool",
                            "namespace": "test",
                            "name": "persistent-service-probe",
                            "attributes": {"status": "ready"},
                        }
                    ],
                )
                self.assertEqual(observation["availability"], "AVAILABLE")
                self.assertEqual(
                    client.capability_inventory("worker-service")["status"], "CURRENT"
                )
                context = ConsumerContext(
                    source_project="integration-harness",
                    consumer_workload_identity="sha256:" + "a" * 64,
                )
                tool_identity = next(
                    item["capability_identity"]
                    for item in observation["capabilities"]
                    if item["kind"] == "tool"
                )
                runtime_identity = workers[0]["description"]["runtime_profile"]["runtime_profile_identity"]
                target = ExecutionTargetReference(
                    worker_identity="worker-service",
                    required_capabilities=("python", "tool:persistent-service-probe"),
                    tool_capability_identity=tool_identity,
                    runtime_identity=runtime_identity,
                    consumer_context_identity=context.context_identity,
                    consumer_authorization_identity="sha256:" + "b" * 64,
                )
                targeted = client.execute_target(
                    target,
                    plan,
                    manifest,
                    consumer_context=context,
                    consumer_authorization_identity="sha256:" + "b" * 64,
                    execution_bundle_archive=archive,
                )
                targeted_retry = client.execute_target(
                    target,
                    plan,
                    manifest,
                    consumer_context=context,
                    consumer_authorization_identity="sha256:" + "b" * 64,
                    execution_bundle_archive=archive,
                )
                before_missing_capability = len(
                    worker.ledger.records(record_type="execution.record")
                )
                client.ingest_capability_observation(
                    "worker-service",
                    [{"kind": "runtime", "namespace": "system", "name": "python"}],
                )
                missing_capability_target = client.execute_target(
                    target,
                    plan,
                    manifest,
                    consumer_context=context,
                    consumer_authorization_identity="sha256:" + "b" * 64,
                    execution_bundle_archive=archive,
                    request_id="sha256:" + "d" * 64,
                )
                self.assertEqual(missing_capability_target["disposition"], "DENIED")
                self.assertEqual(missing_capability_target["reason"], "TARGET_CAPABILITY_MISSING")
                self.assertEqual(
                    len(worker.ledger.records(record_type="execution.record")),
                    before_missing_capability,
                )
                results = client.execute(
                    plan,
                    manifest,
                    worker_id="worker-service",
                    execution_bundle_archive=archive,
                )
                with self.assertRaisesRegex(ProtocolError, "bundle reference"):
                    client._service_transport.request(  # type: ignore[union-attr]
                        "execution.dispatch",
                        {"execution_bundle_archive": str(archive)},
                    )
                scheduled_plan = validate_job_plan(
                    {
                        **{key: value for key, value in plan.items() if key != "job_identity"},
                        "job_id": "persistent-service:scheduler-job",
                    }
                )
                scheduled_results = client.execute(
                    scheduled_plan,
                    manifest,
                    execution_bundle_archive=archive,
                )
                execution_count = len(worker.ledger.records(record_type="execution.record"))
                admin = FabricAdminClient.connect(config.admin_socket_path_value)
                try:
                    admin.revoke_worker("worker-service", reason="target revocation test")
                finally:
                    admin.close()
                revoked_target = client.execute_target(
                    target,
                    plan,
                    manifest,
                    consumer_context=context,
                    consumer_authorization_identity="sha256:" + "b" * 64,
                    execution_bundle_archive=archive,
                    request_id="sha256:" + "c" * 64,
                )
                self.assertEqual(
                    len(worker.ledger.records(record_type="execution.record")),
                    execution_count,
                )
            finally:
                client.close()
                service.request_stop()
                worker_server.request_stop()
                service_thread.join(timeout=5)
                worker_thread.join(timeout=5)
            self.assertFalse(service_thread.is_alive())
            self.assertFalse(worker_thread.is_alive())
            self.assertEqual(bundle_report.category, "PASS")
            self.assertEqual(results[0]["record"]["outcome"], "PASS")
            self.assertEqual(results[0]["worker_identity"], "worker-service")
            self.assertEqual(targeted["disposition"], "EXECUTED")
            self.assertEqual(targeted_retry["disposition"], "DUPLICATE_IDEMPOTENT")
            self.assertEqual(
                targeted_retry["target_execution_evidence_identity"],
                targeted["target_execution_evidence_identity"],
            )
            self.assertEqual(
                targeted["target_execution_evidence"]["worker_identity"],
                "worker-service",
            )
            self.assertEqual(revoked_target["disposition"], "DENIED")
            self.assertEqual(revoked_target["reason"], "TARGET_REVOKED")
            self.assertEqual(scheduled_results[0]["record"]["outcome"], "PASS")
            self.assertEqual(scheduled_results[0]["worker_identity"], "worker-service")


if __name__ == "__main__":
    unittest.main()
