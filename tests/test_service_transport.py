from __future__ import annotations

import os
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mncs_fabric.api import FabricAdminClient, FabricClient
from mncs_fabric.controller_service import ControllerConfig, ControllerService
from mncs_fabric.errors import ProtocolError
from mncs_fabric.service_transport import SERVICE_MAX_FRAME_BYTES, SERVICE_REQUEST_SCHEMA, ServiceClientTransport
from mncs_fabric.canonical import attach_identity


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


if __name__ == "__main__":
    unittest.main()
