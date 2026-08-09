#!/usr/bin/env python3
"""Strict, operator-controlled Linux Fabric worker preflight.

This is deliberately a bootstrap/diagnostic helper, not an execution path.
It reads one explicitly named local configuration file or explicit CLI/env
values.  It never discovers hosts, opens a tunnel, stages candidate material,
or exposes a remote shell through Fabric.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Sequence


DEFAULT_CONFIG = Path(".fabric/operator/raspberry-pi-worker.local.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ssh_args(host: str, user: str, key: Path) -> list[str]:
    return [
        "ssh", "-n", "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        f"{user}@{host}",
    ]


def _run_ssh(host: str, user: str, key: Path, command: str, *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(_ssh_args(host, user, key) + [command], check=False, capture_output=True, text=True, timeout=timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="strict Linux Fabric worker preflight; no endpoint discovery")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--ssh-host")
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-key", type=Path)
    parser.add_argument("--worker-host", help="Fabric TLS address; defaults to ssh_host")
    parser.add_argument("--expected-hostname")
    parser.add_argument("--worker-id")
    parser.add_argument("--controller-id")
    parser.add_argument("--worker-port", type=int)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _operator_values(args: argparse.Namespace) -> argparse.Namespace:
    values: dict[str, object] = {}
    if args.config.is_file():
        raw = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SystemExit("Raspberry Pi operator config must be a JSON object")
        values.update(raw)
    elif args.config != DEFAULT_CONFIG:
        raise SystemExit(f"explicit Raspberry Pi operator config does not exist: {args.config}")
    env = {
        "ssh_host": os.environ.get("MNCS_FABRIC_PI_SSH_HOST"),
        "ssh_user": os.environ.get("MNCS_FABRIC_PI_SSH_USER"),
        "ssh_key": os.environ.get("MNCS_FABRIC_PI_SSH_KEY"),
        "worker_host": os.environ.get("MNCS_FABRIC_PI_WORKER_HOST"),
        "expected_hostname": os.environ.get("MNCS_FABRIC_PI_HOSTNAME"),
        "worker_id": os.environ.get("MNCS_FABRIC_PI_WORKER_ID"),
        "controller_id": os.environ.get("MNCS_FABRIC_PI_CONTROLLER_ID"),
        "worker_port": os.environ.get("MNCS_FABRIC_PI_WORKER_PORT"),
    }
    values.update({key: value for key, value in env.items() if value})
    for name in ("ssh_host", "ssh_user", "ssh_key", "worker_host", "expected_hostname", "worker_id", "controller_id", "worker_port"):
        value = getattr(args, name, None)
        if value is not None:
            values[name] = str(value)
    missing = [name for name in ("ssh_host", "ssh_user", "ssh_key", "expected_hostname", "controller_id") if not values.get(name)]
    if missing:
        raise SystemExit("Raspberry Pi endpoint configuration is incomplete: " + ", ".join(missing))
    args.ssh_host = str(values["ssh_host"])
    args.ssh_user = str(values["ssh_user"])
    args.ssh_key = Path(str(values["ssh_key"])).expanduser()
    args.worker_host = str(values.get("worker_host") or args.ssh_host)
    args.expected_hostname = str(values["expected_hostname"])
    args.worker_id = str(values.get("worker_id") or "raspberry-pi")
    args.controller_id = str(values["controller_id"])
    try:
        args.worker_port = int(values.get("worker_port") or 7443)
    except (TypeError, ValueError) as exc:
        raise SystemExit("worker_port must be an integer") from exc
    args.config_source = str(args.config) if args.config.is_file() else "environment/cli"
    return args


def _diagnostic_record(args: argparse.Namespace, *, outcome: str, observed_hostname: str | None = None, observed: dict[str, Any] | None = None, blocker: str | None = None, diagnostic: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "mncs-fabric.raspberry-pi-preflight.v0.1",
        "record_type": "mncs-fabric.raspberry-pi-preflight",
        "captured_at": _now(),
        "worker_identity": args.worker_id,
        "controller_identity": args.controller_id,
        "endpoint_configuration_source": args.config_source,
        "ssh_host_supplied": args.ssh_host,
        "fabric_worker_host_supplied": args.worker_host,
        "expected_hostname": args.expected_hostname,
        "observed_hostname": observed_hostname,
        "strict_host_key_checking": True,
        "public_key_only": True,
        "direct_fabric_tls": False,
        "ssh_tunnel_used": False,
        "ssh_staged_candidate_material": False,
        "fabric_execution_attempted": False,
        "outcome": outcome,
        "blocker": blocker,
        "diagnostic": diagnostic[-512:] if diagnostic else None,
        "observed": observed,
        "claim_boundary": "operator-controlled Linux/ARM bootstrap preflight; not Fabric execution, attestation, correctness, custody, independence, conformance, or certification evidence",
        "limitations": [
            "This record covers only strict SSH bootstrap diagnostics; candidate execution was not attempted.",
            "A known host key does not establish a usable SSH account or key mapping.",
            "The worker report, if obtained, would remain an authenticated self-report rather than hardware attestation.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _operator_values(build_parser().parse_args(argv))
        if not args.ssh_key.is_file():
            raise SystemExit(f"SSH key does not exist: {args.ssh_key}")
        if not 1 <= args.worker_port <= 65535:
            raise SystemExit("worker port is outside the bounded TCP range")
        hostname = _run_ssh(args.ssh_host, args.ssh_user, args.ssh_key, "hostname")
        if hostname.returncode != 0:
            record = _diagnostic_record(args, outcome="UNKNOWN", blocker="SSH_PUBLICKEY_AUTHENTICATION_FAILED", diagnostic=hostname.stderr)
        else:
            observed_hostname = hostname.stdout.strip()
            facts_command = "python3 -c 'import json,platform,sys,os; print(json.dumps({\"os\":platform.system().lower(),\"os_release\":platform.release(),\"architecture\":platform.machine().lower(),\"python_implementation\":platform.python_implementation(),\"python_version\":platform.python_version(),\"cpu_count\":os.cpu_count()},sort_keys=True))'"
            facts = _run_ssh(args.ssh_host, args.ssh_user, args.ssh_key, facts_command)
            observed: dict[str, Any] | None = None
            if facts.returncode == 0:
                parsed = json.loads(facts.stdout)
                if isinstance(parsed, dict):
                    observed = parsed
            matched = observed_hostname.casefold() == args.expected_hostname.casefold()
            outcome = "PASS" if facts.returncode == 0 and matched and observed is not None else "UNKNOWN"
            record = _diagnostic_record(args, outcome=outcome, observed_hostname=observed_hostname, observed=observed, blocker=None if outcome == "PASS" else "LINUX_PREFLIGHT_FACTS_UNAVAILABLE", diagnostic=facts.stderr)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(record, sort_keys=True))
        return 0 if record["outcome"] == "PASS" else 2
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": type(exc).__name__ + ": " + str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
