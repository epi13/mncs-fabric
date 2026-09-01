from __future__ import annotations

import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import mncs_fabric.capability_broker as capability_broker
from mncs_fabric.api import FabricClient
from mncs_fabric.capability_broker import (
    CapabilityBroker,
    UnixCapabilityBrokerClient,
    UnixCapabilityBrokerServer,
    WindowsCapabilityBroker,
    build_capability_lease,
    build_capability_request,
    build_capability_reconcile_result,
    build_experiment_requirements,
    build_host_privilege_profile,
    check_noninteractive_root,
    validate_capability_arguments,
    validate_capability_audit,
    validate_capability_reconcile_result,
)
from mncs_fabric.errors import ProtocolError, ValidationError
from mncs_fabric.worker import LocalWorker


def _body(*, outcome: str = "PASS", detail: str = "ok", changed: bool = False, data: dict | None = None, stdout: str = "") -> dict:
    return {
        "outcome": outcome,
        "detail": detail,
        "changed": changed,
        "previous_state": None,
        "new_state": None,
        "data": data or {},
        "stdout": stdout,
        "stderr": "",
    }


class StatefulAdapter:
    def __init__(self) -> None:
        self.packages: set[str] = set()
        self.sysctl: dict[str, str] = {}
        self.services: dict[tuple[str, str], str] = {}
        self.directories: set[str] = set()
        self.calls: list[dict] = []

    def execute(self, request: dict) -> dict:
        self.calls.append(request)
        family = request["capability"]
        operation = request["operation"]
        args = request["arguments"]
        if family == "package-management" and operation == "query":
            return _body(data={"packages": {name: name in self.packages for name in args["packages"]}})
        if family == "package-management" and operation == "install":
            before = set(self.packages)
            self.packages.update(args["packages"])
            return _body(changed=before != self.packages)
        if family == "kernel-parameter-management" and operation == "get":
            return _body(data={"key": args["key"], "value": self.sysctl.get(args["key"], "")})
        if family == "kernel-parameter-management" and operation == "set":
            changed = self.sysctl.get(args["key"]) != args["value"]
            self.sysctl[args["key"]] = args["value"]
            return _body(changed=changed, data={"key": args["key"], "value": args["value"]})
        if family == "service-management" and operation == "status":
            state = self.services.get((args["service"], args.get("state", "running")), "inactive")
            return _body(data={"service": args["service"], "state": state})
        if family == "service-management":
            state = {"start": "running", "stop": "stopped", "enable": "enabled", "disable": "disabled"}[operation]
            key = (args["service"], state)
            changed = self.services.get(key) != state
            self.services[key] = state
            return _body(changed=changed, data={"service": args["service"], "state": state})
        if family == "experiment-directory-management" and operation == "inspect":
            return _body(data={"path": args["path"], "exists": args["path"] in self.directories, "directory": args["path"] in self.directories})
        if family == "experiment-directory-management" and operation == "create":
            changed = args["path"] not in self.directories
            self.directories.add(args["path"])
            return _body(changed=changed, data={"path": args["path"]})
        return _body(outcome="SKIPPED", detail=f"unsupported test operation {family}.{operation}")


class CapabilityBrokerTests(unittest.TestCase):
    def test_structured_arguments_reject_shell_and_path_injection(self) -> None:
        with self.assertRaises(ValidationError):
            validate_capability_arguments("package-management", "install", {"packages": ["kernel;id"]})
        with self.assertRaises(ValidationError):
            validate_capability_arguments("service-management", "start", {"service": "fabric-worker && id"})
        with self.assertRaises(ValidationError):
            validate_capability_arguments("kernel-parameter-management", "set", {"key": "kernel.perf_event_paranoid", "value": "$(id)"})
        with self.assertRaises(ValidationError):
            validate_capability_arguments("experiment-directory-management", "create", {"path": "relative/../../escape"})

    def test_profiles_are_explicit_and_worker_identity_bound(self) -> None:
        unrestricted = build_host_privilege_profile(worker_identity="worker-03", mode="unrestricted")
        protected = build_host_privilege_profile(worker_identity="worker-02", mode="capability-broker")
        self.assertEqual(unrestricted["mode"], "unrestricted")
        self.assertIn("package-management", protected["lease_required"])
        self.assertFalse(unrestricted["automatic_leases"])
        with self.assertRaises(ValidationError):
            capability_broker.HostPrivilegeProfile(protected | {"worker_identity": "worker-03"})

    def test_lease_scope_and_audit_are_durable_and_replay_safe(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = StatefulAdapter()
            profile = build_host_privilege_profile(
                worker_identity="worker-02",
                mode="capability-broker",
                allowed_capabilities=["package-management", "experiment-directory-management"],
                experiment_roots=[str(root)],
                service_allowlist=[],
            )
            broker = CapabilityBroker(profile, adapter=adapter, state_path=root / "broker.jsonl")
            request = build_capability_request(worker_identity="worker-02", capability="package-management", operation="install", arguments={"packages": ["fio"]}, experiment_identity="exp")
            denied = broker.request(request)
            self.assertEqual(denied["outcome"], "SKIPPED")
            lease = broker.grant_lease(experiment_identity="exp", capabilities=["package-management"], ttl_seconds=60, operations={"package-management": ["install"]})
            leased_request = build_capability_request(worker_identity="worker-02", capability="package-management", operation="install", arguments={"packages": ["fio"]}, experiment_identity="exp", lease_identity=lease["lease_identity"], requested_at=request["requested_at"])
            allowed = broker.request(leased_request)
            self.assertEqual(allowed["outcome"], "PASS")
            calls_after_first = len(adapter.calls)
            replay = broker.request(leased_request)
            self.assertEqual(replay, allowed)
            self.assertEqual(len(adapter.calls), calls_after_first)
            restarted = CapabilityBroker(profile, adapter=StatefulAdapter(), state_path=root / "broker.jsonl")
            self.assertEqual(restarted.request(leased_request), allowed)
            self.assertTrue(restarted.audit.records(worker_identity="worker-02"))

    def test_reconcile_is_state_based_and_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = StatefulAdapter()
            profile = build_host_privilege_profile(
                worker_identity="worker-02",
                mode="capability-broker",
                allowed_capabilities=["package-management", "kernel-parameter-management", "service-management", "experiment-directory-management"],
                experiment_roots=[str(root)],
                service_allowlist=["fabric-worker"],
                automatic_leases=True,
            )
            broker = CapabilityBroker(profile, adapter=adapter, state_path=root / "broker.jsonl")
            requirements = build_experiment_requirements(
                worker_identity="worker-02",
                experiment_identity="exp",
                capabilities=["package-management", "kernel-parameter-management", "service-management", "experiment-directory-management"],
                packages=["fio"],
                sysctl={"kernel.perf_event_paranoid": "-1"},
                services={"fabric-worker": "running"},
                experiment_directory=str(root / "exp"),
            )
            first = broker.reconcile(requirements, auto_grant_ttl_seconds=60)
            self.assertEqual(first["disposition"], "PASS")
            self.assertTrue(first["changed"])
            second = broker.reconcile(requirements, lease_identity=first["lease_identity"])
            self.assertEqual(second["disposition"], "PASS")
            self.assertFalse(second["changed"])
            self.assertEqual(second["requests"], [])
            self.assertEqual(validate_capability_reconcile_result(second, expected_worker_id="worker-02"), second)

    def test_audit_and_reconcile_contracts_are_strictly_validated(self) -> None:
        request = build_capability_request(
            worker_identity="worker-02",
            capability="system-observation",
            operation="collect",
            arguments={"observations": ["cpuinfo"]},
        )
        result = {
            "outcome": "PASS",
            "detail": "observation collected",
            "changed": False,
            "previous_state": None,
            "new_state": None,
            "data": {"cpuinfo": "bounded"},
            "stdout": "",
            "stderr": "",
        }
        with TemporaryDirectory() as directory:
            audit_store = capability_broker.CapabilityAuditStore(Path(directory) / "audit.jsonl")
            audit = audit_store.record(request=request, result=result, worker_identity="worker-02")
            self.assertEqual(validate_capability_audit(audit, expected_worker_id="worker-02"), audit)
            with self.assertRaises(ValidationError):
                validate_capability_audit(audit | {"worker_identity": "worker-03"})
        reconcile = build_capability_reconcile_result(
            worker_identity="worker-02",
            experiment_identity="exp",
            requirements_identity="sha256:" + "a" * 64,
            lease_identity=None,
            disposition="PASS",
            requests=[request],
            observations=[],
            results=[],
            changed=False,
        )
        self.assertEqual(validate_capability_reconcile_result(reconcile), reconcile)

    def test_linux_adapter_uses_fixed_argv(self) -> None:
        profile = build_host_privilege_profile(worker_identity="worker-02", mode="capability-broker", service_allowlist=["fabric-worker"])
        commands: list[list[str]] = []

        def runner(argv: list[str]) -> dict:
            commands.append(argv)
            return {"returncode": 0, "stdout": "active\n", "stderr": "", "timed_out": False}

        with patch.object(capability_broker, "_system_executable", side_effect=lambda name: "/usr/bin/" + name):
            adapter = capability_broker.LinuxCapabilityBroker(profile, runner=runner, package_manager="apt-get")
            request = build_capability_request(worker_identity="worker-02", capability="service-management", operation="start", arguments={"service": "fabric-worker"})
            adapter.execute(request)
            self.assertEqual(commands[0], ["/usr/bin/systemctl", "start", "fabric-worker"])
            self.assertNotIn(";", " ".join(commands[0]))

    def test_windows_adapter_maps_typed_service_operations_to_fixed_argv(self) -> None:
        profile = build_host_privilege_profile(
            worker_identity="windows-worker",
            mode="windows-capability-broker",
            platform="windows",
            allowed_capabilities=["service-management"],
            service_allowlist=["mncs-experiment"],
        )
        commands: list[list[str]] = []

        def runner(argv: list[str]) -> dict:
            commands.append(argv)
            return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}

        adapter = WindowsCapabilityBroker(profile, runner=runner)
        restart = build_capability_request(
            worker_identity="windows-worker",
            capability="service-management",
            operation="restart",
            arguments={"service": "mncs-experiment"},
        )
        adapter.execute(restart)
        self.assertEqual(
            commands,
            [
                [r"C:\Windows\System32\sc.exe", "stop", "mncs-experiment"],
                [r"C:\Windows\System32\sc.exe", "start", "mncs-experiment"],
            ],
        )
        commands.clear()
        enable = build_capability_request(
            worker_identity="windows-worker",
            capability="service-management",
            operation="enable",
            arguments={"service": "mncs-experiment"},
        )
        adapter.execute(enable)
        self.assertEqual(commands, [[r"C:\Windows\System32\sc.exe", "config", "mncs-experiment", "start=", "auto"]])

    def test_noninteractive_root_check_never_prompts(self) -> None:
        commands: list[list[str]] = []
        result = check_noninteractive_root(runner=lambda argv: commands.append(argv) or {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False})
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(commands, [["sudo", "-n", "true"]])

    def test_authenticated_worker_protocol_carries_capability_result(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            profile = build_host_privilege_profile(worker_identity="worker-02", mode="capability-broker", allowed_capabilities=["hardware-observation"])
            worker = LocalWorker("worker-02", root, root / "worker.jsonl", capability_broker=CapabilityBroker(profile, adapter=StatefulAdapter(), state_path=root / "broker.jsonl"))
            client = FabricClient("controller", root / "controller.jsonl")
            client.register_local_worker(worker)
            result = client.request_capability("worker-02", "hardware-observation", "collect", {"observations": ["cpu"]})
            self.assertEqual(result["outcome"], "SKIPPED")
            self.assertEqual(result["worker_identity"], "worker-02")

    def test_unix_broker_checks_peer_and_canonical_frame(self) -> None:
        if os.name != "posix":
            self.skipTest("Unix peer credential test requires POSIX")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            profile = build_host_privilege_profile(worker_identity="worker-02", mode="capability-broker", allowed_capabilities=["hardware-observation"])
            broker = CapabilityBroker(profile, adapter=StatefulAdapter())
            socket_path = root / "broker.sock"
            server = UnixCapabilityBrokerServer(broker, socket_path, allowed_uids=[os.getuid()])
            server.bind()
            thread = threading.Thread(target=server.serve_once)
            thread.start()
            request = build_capability_request(worker_identity="worker-02", capability="hardware-observation", operation="collect", arguments={"observations": ["cpu"]})
            result = UnixCapabilityBrokerClient(socket_path).request(request)
            thread.join(timeout=5)
            self.assertEqual(result["worker_identity"], "worker-02")
            self.assertEqual(server.handled_requests, 1)

            denied_server = UnixCapabilityBrokerServer(broker, root / "denied.sock", allowed_uids=[os.getuid() + 1])
            denied_server.bind()
            denied_thread = threading.Thread(target=denied_server.serve_once)
            denied_thread.start()
            with self.assertRaises((ConnectionError, ProtocolError, OSError)):
                UnixCapabilityBrokerClient(root / "denied.sock").request(request)
            denied_thread.join(timeout=5)
            self.assertIsNotNone(denied_server.last_error)

    def test_lease_expiry_and_cleanup_are_explicit(self) -> None:
        with TemporaryDirectory() as directory:
            store = capability_broker.CapabilityLeaseStore(Path(directory) / "leases.jsonl")
            lease = build_capability_lease(worker_identity="worker-02", capabilities=["package-management"], ttl_seconds=60, granted_at="2026-01-01T00:00:00Z")
            store.grant(lease)
            expired = store.expire(now="2026-01-01T00:01:00Z")
            self.assertEqual(expired[0]["state"], "EXPIRED")
            cleaned = store.cleanup(now="2026-01-01T00:01:00Z")
            self.assertEqual(cleaned[0]["state"], "CLEANED")
            self.assertFalse(store.is_active(lease["lease_identity"], worker_identity="worker-02", capability="package-management", operation="install"))


if __name__ == "__main__":
    unittest.main()
