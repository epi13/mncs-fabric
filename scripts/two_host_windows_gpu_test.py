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
from pathlib import Path
import subprocess
from typing import Sequence


def _ssh_args(host: str, user: str, key: Path) -> list[str]:
    return ["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", f"{user}@{host}"]


def _run_ssh(host: str, user: str, key: Path, command: str, *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    # The command is a fixed diagnostic selected by this script, not a
    # candidate execution channel.  Windows receives PowerShell syntax.
    return subprocess.run(_ssh_args(host, user, key) + ["powershell", "-NoProfile", "-NonInteractive", "-Command", command], check=False, capture_output=True, text=True, timeout=timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="strict Fedora-to-Windows Fabric worker preflight")
    parser.add_argument("--ssh-host", required=True, help="explicit Windows SSH host or configured alias")
    parser.add_argument("--ssh-user", required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--worker-id", default="collamore02-windows")
    parser.add_argument("--controller-id", required=True)
    parser.add_argument("--worker-port", type=int, default=7443)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics-only", action="store_true", help="only verify the explicit Windows bootstrap endpoint")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
        "ssh_host_supplied": args.ssh_host,
        "expected_hostname": args.expected_hostname,
        "observed_hostname": observed,
        "strict_host_key_checking": True,
        "ssh_tunnel_used": False,
        "candidate_material_staged_by_ssh": False,
        "diagnostics_only": bool(args.diagnostics_only),
        "outcome": "PASS" if result.returncode == 0 and observed == args.expected_hostname else "UNKNOWN",
        "diagnostic": result.stderr[-1024:] if result.stderr else None,
        "claim_boundary": "operator-controlled Windows bootstrap preflight; not Fabric execution evidence",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, sort_keys=True))
    return 0 if record["outcome"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
