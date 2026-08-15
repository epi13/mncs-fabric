from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.errors import ValidationError
from mncs_fabric.inventory import (
    INVENTORY_SCHEMA,
    build_worker_inventory,
    collect_worker_inventory,
    discover_search_path,
    discover_service,
    redact_text,
    validate_worker_inventory,
)
from mncs_fabric.worker import LocalWorker


def sample_inventory(worker_id: str = "worker-a", *, ollama_manager: str = "process", models: list | None = None, harness: str | None = None, git=True):
    # Health certification actually executes advertised python/git. Fixtures
    # must use host-reachable paths so Windows CI is not failed by /usr/bin/*.
    python = sys.executable
    git_path = shutil.which("git") if git else None
    git_present = bool(git and git_path)
    return build_worker_inventory(
        worker_id=worker_id,
        identity={
            "hostname": "host-a",
            "platform": "linux",
            "os": "linux",
            "distribution": "fedora",
            "os_version": "42",
            "kernel": "6.11",
            "architecture": "x86_64",
        },
        hardware={
            "cpu_count": 8,
            "ram_bytes": 16 * 1024 ** 3,
            "ram_available_bytes": 8 * 1024 ** 3,
            "disk_bytes": 500 * 1024 ** 3,
            "disk_available_bytes": 200 * 1024 ** 3,
            "accelerators": [],
        },
        fabric={
            "worker_version": "0.2.0a21",
            "protocol_version": "mncs-fabric.protocol.v0.1",
            "harness_version": harness,
            "agent_version": "0.2.0a21",
            "python_executable": python,
        },
        tools=[
            {"name": "git", "present": git_present, "path": git_path if git_present else None, "version": "git version 2.45.0" if git_present else None, "detail": None},
            {"name": "gh", "present": True, "path": "/usr/bin/gh", "version": "gh 2.50.0", "detail": None},
            {"name": "python", "present": True, "path": python, "version": "3.13.0", "detail": "CPython"},
        ],
        runtimes=[
            {
                "name": "ollama",
                "present": True,
                "install_type": "unknown",
                "service_type": ollama_manager,
                "endpoint": "http://127.0.0.1:11434",
                "version": "0.6.0",
                "reachable": True,
                "models": models or [{"name": "qwen3:8b", "digest": "sha256:abc", "size_bytes": 1, "family": "qwen3", "parameter_size": "8B", "quantization": "Q4_K_M"}],
            }
        ],
        repositories=[],
        services=[
            {"name": "fabric-worker", "present": True, "manager": "systemd-user", "unit": "mncs-fabric-worker-rendezvous@worker-a.service", "state": "running", "install_type": "package"},
            {"name": "ollama", "present": True, "manager": ollama_manager, "unit": "127.0.0.1:11434", "state": "running", "install_type": "unknown"},
            {"name": "mncs-fabric-controller", "present": False, "manager": "absent", "unit": None, "state": "absent", "install_type": "absent"},
        ],
        health={
            "load_1m": 0.2,
            "ram_pressure": "ok",
            "disk_pressure": "ok",
            "pending_reboot": False,
            "active_jobs": 0,
            "maintenance_eligible": True,
        },
        credentials=[
            {"name": "github-cli", "available": True, "detail": "authenticated"},
            {"name": "joern", "available": False, "detail": "absent"},
            {"name": "forge", "available": False, "detail": "absent"},
        ],
        captured_at="2026-08-14T00:00:00Z",
    )


class InventoryTests(unittest.TestCase):
    def test_collect_and_validate_local_inventory(self) -> None:
        inventory = collect_worker_inventory("local-inventory")
        checked = validate_worker_inventory(inventory, expected_worker_id="local-inventory")
        self.assertEqual(checked["schema_version"], INVENTORY_SCHEMA)
        self.assertEqual(checked["identity"]["platform"], checked["identity"]["os"])
        self.assertTrue(any(item["name"] == "python" and item["present"] for item in checked["tools"]))
        self.assertTrue(any(item["name"] == "ollama" for item in checked["runtimes"]))

    def test_search_path_discovery_is_generic(self) -> None:
        discovered = discover_search_path()
        self.assertIn("process", discovered)
        self.assertIn("effective", discovered)
        self.assertTrue(discovered["effective"])
        from pathlib import Path as _Path

        for item in discovered.get("extra") or []:
            self.assertTrue(_Path(item).is_dir(), item)

    def test_inventory_identity_rejects_tampering(self) -> None:
        inventory = sample_inventory()
        tampered = dict(inventory)
        tampered["identity"] = dict(inventory["identity"])
        tampered["identity"]["hostname"] = "other-host"
        with self.assertRaises(ValidationError):
            validate_worker_inventory(tampered)

    def test_redaction_removes_tokens(self) -> None:
        text = redact_text("Authorization=Bearer ghp_abcdefghijklmnopqrstuvwxyz012345 and password=supersecret")
        self.assertNotIn("ghp_", text)
        self.assertNotIn("supersecret", text)
        self.assertIn("[redacted", text)

    def test_ollama_service_discovery_does_not_assume_systemd(self) -> None:
        service = discover_service("definitely-missing-mncs-unit", units=("definitely-missing-mncs-unit.service",))
        self.assertIn(service["manager"], {"absent", "unknown", "process"})
        if service["manager"] == "absent":
            self.assertEqual(service["state"], "absent")

    def test_worker_inventory_protocol_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            worker = LocalWorker("inventory-worker", bundle, root / "worker.jsonl")
            inventory = worker.inventory()
            self.assertEqual(validate_worker_inventory(inventory)["worker_identity"], "inventory-worker")
