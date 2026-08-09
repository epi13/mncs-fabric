#!/usr/bin/env python3
"""Operator-controlled Fedora-to-Windows Fabric preflight.

This harness intentionally requires every Windows endpoint parameter.  It
uses strict OpenSSH host-key checking for bootstrap and diagnostics only; the
candidate workload must still be dispatched through Fabric's direct TLS
transport by the caller.  No LAN discovery or SSH tunnel is implemented.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
from typing import Sequence


def _ssh_args(host: str, user: str, key: Path) -> list[str]:
    return ["ssh", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", f"{user}@{host}"]


def _run_ssh(host: str, user: str, key: Path, command: str, *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    # The command is a fixed diagnostic selected by this script, not a
    # candidate execution channel.  Windows receives PowerShell syntax.
    return subprocess.run(_ssh_args(host, user, key) + ["powershell", "-NoProfile", "-NonInteractive", "-Command", command], check=False, capture_output=True, text=True, timeout=timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="strict Fedora-to-Windows Fabric worker preflight")
    parser.add_argument("--config", type=Path, default=Path(".fabric/operator/windows-worker.local.json"), help="explicit local operator configuration; no endpoint discovery is performed")
    parser.add_argument("--ssh-host", help="explicit Windows SSH host or configured alias")
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-key", type=Path)
    parser.add_argument("--expected-hostname")
    parser.add_argument("--worker-id")
    parser.add_argument("--controller-id")
    parser.add_argument("--worker-port", type=int, default=7443)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics-only", action="store_true", help="only verify the explicit Windows bootstrap endpoint")
    return parser


def _operator_values(args: argparse.Namespace) -> argparse.Namespace:
    """Resolve only an explicitly named config file and CLI overrides."""

    values: dict[str, object] = {}
    if args.config is not None and args.config.is_file():
        raw = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SystemExit("Windows operator config must be a JSON object")
        values.update(raw)
    elif args.config != Path(".fabric/operator/windows-worker.local.json") and args.config is not None:
        raise SystemExit(f"explicit Windows operator config does not exist: {args.config}")
    env = {
        "ssh_host": os.environ.get("MNCS_FABRIC_WINDOWS_SSH_HOST"),
        "ssh_user": os.environ.get("MNCS_FABRIC_WINDOWS_SSH_USER"),
        "ssh_key": os.environ.get("MNCS_FABRIC_WINDOWS_SSH_KEY"),
        "expected_hostname": os.environ.get("MNCS_FABRIC_WINDOWS_HOSTNAME"),
        "worker_id": os.environ.get("MNCS_FABRIC_WINDOWS_WORKER_ID"),
        "controller_id": os.environ.get("MNCS_FABRIC_WINDOWS_CONTROLLER_ID"),
    }
    values.update({key: value for key, value in env.items() if value})
    for name in ("ssh_host", "ssh_user", "ssh_key", "expected_hostname", "worker_id", "controller_id"):
        cli_value = getattr(args, name)
        if cli_value is not None:
            values[name] = str(cli_value)
    missing = [name for name in ("ssh_host", "ssh_user", "ssh_key", "expected_hostname", "controller_id") if not values.get(name)]
    if missing:
        raise SystemExit("Windows endpoint configuration is incomplete: " + ", ".join(missing))
    args.ssh_host = str(values["ssh_host"])
    args.ssh_user = str(values["ssh_user"])
    args.ssh_key = Path(str(values["ssh_key"])).expanduser()
    args.expected_hostname = str(values["expected_hostname"])
    args.worker_id = str(values.get("worker_id") or "collamore02-windows")
    args.controller_id = str(values["controller_id"])
    args.config_source = str(args.config) if args.config.is_file() else "environment/cli"
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _operator_values(build_parser().parse_args(argv))
    if not args.ssh_key.is_file():
        raise SystemExit(f"SSH key does not exist: {args.ssh_key}")
    if not 1 <= args.worker_port <= 65535:
        raise SystemExit("worker port is outside the bounded TCP range")
    result = _run_ssh(args.ssh_host, args.ssh_user, args.ssh_key, "$env:COMPUTERNAME")
    observed = result.stdout.strip()
    record = {
        "schema_version": "mncs-fabric.windows-worker-preflight.v0.1",
        "worker_identity": args.worker_id,
        "controller_identity": args.controller_id,
        "endpoint_configuration_source": args.config_source,
        "ssh_host_supplied": args.ssh_host,
        "expected_hostname": args.expected_hostname,
        "observed_hostname": observed,
        "strict_host_key_checking": True,
        "ssh_tunnel_used": False,
        "candidate_material_staged_by_ssh": False,
        "diagnostics_only": bool(args.diagnostics_only),
        "outcome": "PASS" if result.returncode == 0 and observed.casefold() == args.expected_hostname.casefold() else "UNKNOWN",
        "diagnostic": result.stderr[-1024:] if result.stderr else None,
        "claim_boundary": "operator-controlled Windows bootstrap preflight; not Fabric execution evidence",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0 if record["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
