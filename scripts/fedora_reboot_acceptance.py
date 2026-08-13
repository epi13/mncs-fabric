#!/usr/bin/env python3
"""Two-phase physical acceptance for a commissioned Fedora rendezvous worker.

SSH is used only for host lifecycle and diagnostics. The controller observation,
bundle transfer, exact-worker dispatch, and result travel through Fabric. The
post-reboot phase deliberately observes the higher session generation before it
opens its first post-boot SSH connection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mncs_fabric.api import FabricClient  # noqa: E402
from mncs_fabric.artifacts import verify_manifest  # noqa: E402
from mncs_fabric.bundles import build_bundle_archive  # noqa: E402
from mncs_fabric.commissioning import write_protected_json  # noqa: E402
from mncs_fabric.enrollment import TrustStore  # noqa: E402
from mncs_fabric.errors import FabricError  # noqa: E402
from mncs_fabric.io import load_json  # noqa: E402
from mncs_fabric.models import validate_job_plan  # noqa: E402

SCHEMA = "mncs-fabric.fedora-reboot-acceptance.v0.1"
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(value: str, field: str) -> str:
    if not _IDENTITY.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _safe_absolute(path: Path, field: str) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute() or "\x00" in str(value):
        raise ValueError(f"{field} must be an absolute path")
    return value


def _sha256_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"presence": "ABSENT", "sha256": None}
    path = _safe_absolute(path, "registry")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("registry evidence path must be a regular non-symbolic file")
    return {
        "presence": "PRESENT",
        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    }


class Remote:
    def __init__(self, *, alias: str | None, host: str | None, user: str | None, key: Path | None) -> None:
        if alias is not None:
            _identity(alias, "ssh_alias")
            if any(value is not None for value in (host, user, key)):
                raise ValueError("SSH alias mode cannot be combined with host/user/key")
            self.destination = alias
            self.options = [
                "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10",
            ]
        else:
            if host is None or user is None or key is None:
                raise ValueError("explicit SSH host, user, and key are required")
            _identity(user, "ssh_user")
            key = _safe_absolute(key, "ssh_key")
            if key.is_symlink() or not key.is_file():
                raise ValueError("SSH key must be a regular non-symbolic file")
            self.destination = f"{user}@{host}"
            self.options = [
                "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10",
            ]

    def run(self, command: str, *, timeout: float = 20) -> str:
        completed = subprocess.run(
            ["ssh", "-n", *self.options, self.destination, command],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"remote diagnostic failed ({completed.returncode}): {completed.stderr.strip()}"
            )
        return completed.stdout.strip()

    def reboot(self) -> dict[str, Any]:
        completed = subprocess.run(
            ["ssh", "-n", *self.options, self.destination, "sudo -n systemctl reboot"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.returncode not in {0, 255}:
            raise RuntimeError(
                f"remote reboot request failed ({completed.returncode}): {completed.stderr.strip()}"
            )
        return {"requested_at": _now(), "ssh_return_code": completed.returncode}


def _remote(args: argparse.Namespace) -> Remote:
    return Remote(alias=args.ssh_alias, host=args.ssh_host, user=args.ssh_user, key=args.ssh_key)


def _remote_facts(remote: Remote, *, worker_id: str, state_root: Path) -> dict[str, Any]:
    unit = f"mncs-fabric-worker-rendezvous@{worker_id}.service"
    installation_text = remote.run(
        "cat " + shlex.quote(str(_safe_absolute(state_root, "worker_state_root") / "installation.json"))
    )
    installation = json.loads(installation_text)
    if installation.get("worker_id") != worker_id:
        raise RuntimeError("remote installation identity does not match the worker")
    return {
        "boot_id": remote.run("cat /proc/sys/kernel/random/boot_id"),
        "hostname": remote.run("hostname"),
        "addresses": sorted(remote.run("hostname -I").split()),
        "unit": unit,
        "unit_enabled": remote.run("systemctl --user is-enabled " + shlex.quote(unit)),
        "unit_active": remote.run("systemctl --user is-active " + shlex.quote(unit)),
        "linger": remote.run("loginctl show-user \"$USER\" -p Linger --value"),
        "installation_identity": installation.get("installation_identity"),
        "credential_identity": installation.get("credential_identity"),
        "fabric_commit": remote.run("cat \"$HOME/.local/share/mncs-fabric/fabric-revision.txt\""),
    }


def _worker_status(socket_path: Path, worker_id: str, *, controller_id: str | None = None) -> dict[str, Any]:
    client = FabricClient.connect(socket_path, client_identity="fedora-reboot-acceptance")
    try:
        controller = client.controller_status()
        if controller_id is not None and controller.get("controller_id") != controller_id:
            raise RuntimeError("controller service identity does not match acceptance input")
        status = client.fleet_status(worker_id)
    finally:
        client.close()
    return status


def _require_available(status: dict[str, Any]) -> int:
    generation = status.get("session_generation")
    if status.get("membership_status") != "ENROLLED":
        raise RuntimeError("worker is not an enrolled Fabric member")
    if status.get("availability") != "AVAILABLE" or status.get("available") is not True:
        raise RuntimeError("worker is not currently AVAILABLE")
    if not isinstance(generation, int) or generation < 1:
        raise RuntimeError("worker has no valid rendezvous session generation")
    return generation


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    worker_id = _identity(args.worker_id, "worker_id")
    controller_id = _identity(args.controller_id, "controller_id")
    status = _worker_status(args.socket, worker_id, controller_id=controller_id)
    generation = _require_available(status)
    trust = TrustStore(args.controller_trust_state).lookup("worker", worker_id)
    if trust is None or not trust.get("active"):
        raise RuntimeError("controller trust has no active worker certificate binding")
    remote_facts = _remote_facts(
        _remote(args), worker_id=worker_id, state_root=args.worker_state_root
    )
    if remote_facts["unit_enabled"] != "enabled" or remote_facts["unit_active"] != "active":
        raise RuntimeError("worker user service is not enabled and active")
    if remote_facts["linger"] != "yes":
        raise RuntimeError("worker user manager does not have linger enabled")
    if not _COMMIT.fullmatch(args.fabric_commit) or remote_facts["fabric_commit"] != args.fabric_commit:
        raise RuntimeError("worker installed Fabric revision does not match the expected commit")
    evidence = {
        "schema_version": SCHEMA,
        "record_type": "mncs-fabric.fedora-reboot-acceptance",
        "status": "PREPARED",
        "prepared_at": _now(),
        "controller_identity": controller_id,
        "worker_identity": worker_id,
        "controller_fabric_commit": args.fabric_commit,
        "worker_fabric_commit": remote_facts["fabric_commit"],
        "controller_socket_transport": "LOCAL_UNIX_SOCKET",
        "consumer_knows_worker_endpoint": False,
        "worker_certificate_fingerprint": trust["certificate_fingerprint"],
        "registry_before": _sha256_file(args.registry),
        "before": {
            "session_generation": generation,
            "availability": status["availability"],
            **remote_facts,
        },
        "claim_boundary": "operator-controlled physical acceptance; no attestation, semantic correctness, custody, independence, conformance, or certification claim",
    }
    write_protected_json(args.state, evidence)
    return evidence


def request_reboot(args: argparse.Namespace) -> dict[str, Any]:
    if not args.yes_reboot:
        raise ValueError("--yes-reboot is required for the disruptive reboot action")
    prepared = load_json(args.state)
    if prepared.get("schema_version") != SCHEMA or prepared.get("status") != "PREPARED":
        raise RuntimeError("reboot state is not a prepared Fedora acceptance record")
    current_boot = _remote(args).run("cat /proc/sys/kernel/random/boot_id")
    if current_boot != prepared.get("before", {}).get("boot_id"):
        raise RuntimeError("worker boot identity changed before the requested reboot")
    result = _remote(args).reboot()
    prepared["reboot_request"] = result
    write_protected_json(args.state, prepared)
    return result


def _wait_for_reconnect(socket_path: Path, controller_id: str, worker_id: str, previous: int, timeout: float) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            last = _worker_status(socket_path, worker_id, controller_id=controller_id)
            generation = last.get("session_generation")
            if last.get("availability") == "AVAILABLE" and isinstance(generation, int) and generation > previous:
                return last, _now()
        except (FabricError, OSError):
            pass
        time.sleep(1)
    raise RuntimeError(f"worker did not reconnect with a higher generation; last={last!r}")


def verify(args: argparse.Namespace) -> dict[str, Any]:
    prepared = load_json(args.state)
    if prepared.get("schema_version") != SCHEMA or prepared.get("status") != "PREPARED":
        raise RuntimeError("verification state is not a prepared Fedora acceptance record")
    worker_id = str(prepared["worker_identity"])
    before = prepared["before"]

    # This is deliberately the first post-reboot observation. No SSH is opened
    # until the controller reports a higher authenticated session generation.
    status, observed_at = _wait_for_reconnect(
        args.socket, str(prepared["controller_identity"]), worker_id,
        int(before["session_generation"]), args.wait_seconds
    )
    after = _remote_facts(
        _remote(args), worker_id=worker_id, state_root=args.worker_state_root
    )
    if after["boot_id"] == before["boot_id"]:
        raise RuntimeError("worker boot identity did not change")
    if after["installation_identity"] != before["installation_identity"] or after["credential_identity"] != before["credential_identity"]:
        raise RuntimeError("worker installation or credential identity changed across reboot")
    if after["unit_enabled"] != "enabled" or after["unit_active"] != "active" or after["linger"] != "yes":
        raise RuntimeError("worker service did not return under the lingering user manager")
    registry_after = _sha256_file(args.registry)
    if registry_after != prepared["registry_before"]:
        raise RuntimeError("controller registry state changed across reboot")
    trust = TrustStore(args.controller_trust_state).lookup("worker", worker_id)
    if trust is None or not trust.get("active") or trust.get("certificate_fingerprint") != prepared["worker_certificate_fingerprint"]:
        raise RuntimeError("worker certificate trust binding changed across reboot")

    manifest = verify_manifest(args.bundle_root, load_json(args.manifest))
    plan = validate_job_plan(load_json(args.plan))
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "reboot-acceptance.zip"
        report = build_bundle_archive(args.bundle_root, archive)
        client = FabricClient.connect(args.socket, client_identity="fedora-reboot-acceptance")
        try:
            results = client.execute(
                plan,
                manifest,
                worker_id=worker_id,
                request_id=f"reboot-acceptance:{before['session_generation']}:{status['session_generation']}",
                execution_bundle_archive=archive,
            )
        finally:
            client.close()
    if len(results) != 1 or results[0].get("worker_identity") != worker_id or results[0].get("disposition") != "EXECUTED":
        raise RuntimeError("post-reboot exact-worker Fabric dispatch did not execute")

    evidence = {
        **prepared,
        "status": "PASS",
        "verified_at": _now(),
        "physical_test": True,
        "controller_observed_reconnect_before_acceptance_ssh": True,
        "after": {
            "session_generation": status["session_generation"],
            "availability": status["availability"],
            "controller_observed_at": observed_at,
            **after,
        },
        "invariants": {
            "same_logical_identity": status.get("worker_id") == worker_id,
            "higher_session_generation": status["session_generation"] > before["session_generation"],
            "same_certificate_fingerprint": True,
            "same_installation_identity": True,
            "same_credential_identity": True,
            "registry_unchanged": True,
            "manual_worker_launch": False,
            "consumer_worker_endpoint_knowledge": False,
            "address_changed": after["addresses"] != before["addresses"],
        },
        "execution": {
            "disposition": results[0]["disposition"],
            "worker_identity": results[0]["worker_identity"],
            "record_identity": results[0].get("record_identity"),
            "receipt_identity": results[0].get("receipt_identity"),
            "bundle_identity": report.bundle_identity,
            "archive_identity": report.archive_identity,
        },
        "limitations": [
            "SSH requested the reboot and read post-boot host diagnostics; Fabric carried the workload.",
            "Reconnect-before-SSH proves return before this helper's first post-boot remote login, not absence of every other user session.",
            "DHCP independence is physically demonstrated only when address_changed is true.",
        ],
    }
    write_protected_json(args.output, evidence)
    return evidence


def _add_remote(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ssh-alias")
    group.add_argument("--ssh-host")
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-key", type=Path)
    parser.add_argument("--worker-state-root", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Physically verify Fedora worker reboot persistence")
    sub = parser.add_subparsers(dest="command", required=True)
    before = sub.add_parser("prepare")
    before.add_argument("--socket", type=Path, required=True)
    before.add_argument("--controller-id", required=True)
    before.add_argument("--worker-id", required=True)
    before.add_argument("--fabric-commit", required=True)
    before.add_argument("--controller-trust-state", type=Path, required=True)
    before.add_argument("--registry", type=Path)
    before.add_argument("--state", type=Path, required=True)
    _add_remote(before)
    reboot = sub.add_parser("request-reboot")
    reboot.add_argument("--state", type=Path, required=True)
    reboot.add_argument("--yes-reboot", action="store_true")
    _add_remote(reboot)
    after = sub.add_parser("verify")
    after.add_argument("--state", type=Path, required=True)
    after.add_argument("--output", type=Path, required=True)
    after.add_argument("--socket", type=Path, required=True)
    after.add_argument("--controller-trust-state", type=Path, required=True)
    after.add_argument("--registry", type=Path)
    after.add_argument("--bundle-root", type=Path, required=True)
    after.add_argument("--manifest", type=Path, required=True)
    after.add_argument("--plan", type=Path, required=True)
    after.add_argument("--wait-seconds", type=float, default=300)
    _add_remote(after)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "prepare":
            result = prepare(args)
        elif args.command == "request-reboot":
            result = request_reboot(args)
        else:
            if not 5 <= args.wait_seconds <= 1800:
                raise ValueError("wait-seconds must be between 5 and 1800")
            result = verify(args)
        print(json.dumps({"outcome": result.get("status", "PASS"), "result": result}, sort_keys=True, separators=(",", ":")))
        return 0
    except (FabricError, OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
