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


def _ssh_options(*, identities_only: bool) -> list[str]:
    options = [
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
    ]
    if identities_only:
        options[0:0] = ["-o", "IdentitiesOnly=yes"]
    else:
        # Alias mode may intentionally use an already configured agent.  The
        # authentication method remains public-key-only and all interactive
        # or password fallbacks remain disabled above.
        options[0:0] = ["-o", "IdentitiesOnly=no"]
    return options


def _ssh_args(host: str, user: str, key: Path) -> list[str]:
    return [
        "ssh", "-n", "-i", str(key),
        *_ssh_options(identities_only=True),
        f"{user}@{host}",
    ]


def _alias_ssh_args(alias: str, key: Path | None = None) -> list[str]:
    command = ["ssh", "-n", *_ssh_options(identities_only=key is not None)]
    if key is not None:
        command[2:2] = ["-i", str(key)]
    return command + [alias]


def _run_ssh(destination: list[str], command: str, *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(destination + [command], check=False, capture_output=True, text=True, timeout=timeout)


def _resolve_alias(alias: str) -> tuple[dict[str, object] | None, subprocess.CompletedProcess[str]]:
    result = subprocess.run(
        ["ssh", "-G", *_ssh_options(identities_only=False), alias],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None, result
    values: dict[str, object] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if not separator:
            continue
        if key == "hostname":
            values["hostname"] = value
        elif key == "user":
            values["user"] = value
        elif key == "port":
            values["port"] = value
        elif key == "proxycommand":
            values["proxy_command_configured"] = value not in {"none", ""}
        elif key == "pubkeyauthentication":
            values["public_key_authentication"] = value.lower() in {"yes", "true", "on"}
    if not values.get("hostname") or not values.get("user") or not values.get("port"):
        return None, subprocess.CompletedProcess(result.args, 2, "", "ssh -G did not return a usable effective endpoint")
    return values, result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="strict Linux Fabric worker preflight; no endpoint discovery")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--ssh-alias", help="explicit OpenSSH alias; uses the operator's configured key/agent")
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
        "ssh_alias": os.environ.get("MNCS_FABRIC_PI_SSH_ALIAS"),
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
    for name in ("ssh_alias", "ssh_host", "ssh_user", "ssh_key", "worker_host", "expected_hostname", "worker_id", "controller_id", "worker_port"):
        value = getattr(args, name, None)
        if value is not None:
            values[name] = str(value)
    if values.get("ssh_alias"):
        explicit_endpoint_fields = [name for name in ("ssh_host", "ssh_user", "ssh_key") if values.get(name)]
        if explicit_endpoint_fields:
            raise SystemExit("ssh_alias cannot be combined with explicit SSH host/user/key: " + ", ".join(explicit_endpoint_fields))
        missing = [name for name in ("ssh_alias", "expected_hostname", "controller_id") if not values.get(name)]
    else:
        missing = [name for name in ("ssh_host", "ssh_user", "ssh_key", "expected_hostname", "controller_id") if not values.get(name)]
    if missing:
        raise SystemExit("Raspberry Pi endpoint configuration is incomplete: " + ", ".join(missing))
    args.ssh_alias = str(values["ssh_alias"]) if values.get("ssh_alias") else None
    args.ssh_host = str(values["ssh_host"]) if values.get("ssh_host") else None
    args.ssh_user = str(values["ssh_user"]) if values.get("ssh_user") else None
    args.ssh_key = Path(str(values["ssh_key"])).expanduser() if values.get("ssh_key") else None
    args.ssh_user_supplied = bool(values.get("ssh_user"))
    args.ssh_key_supplied = bool(values.get("ssh_key"))
    args.worker_host = str(values.get("worker_host")) if values.get("worker_host") else None
    args.expected_hostname = str(values["expected_hostname"])
    args.worker_id = str(values.get("worker_id") or "raspberry-pi")
    args.controller_id = str(values["controller_id"])
    try:
        args.worker_port = int(values.get("worker_port") or 7443)
    except (TypeError, ValueError) as exc:
        raise SystemExit("worker_port must be an integer") from exc
    args.config_source = str(args.config) if args.config.is_file() else "environment/cli"
    return args


def _diagnostic_record(args: argparse.Namespace, *, outcome: str, observed_hostname: str | None = None, observed: dict[str, Any] | None = None, blocker: str | None = None, diagnostic: str | None = None, resolved: dict[str, object] | None = None) -> dict[str, Any]:
    return {
        "schema_version": "mncs-fabric.raspberry-pi-preflight.v0.1",
        "record_type": "mncs-fabric.raspberry-pi-preflight",
        "captured_at": _now(),
        "worker_identity": args.worker_id,
        "controller_identity": args.controller_id,
        "endpoint_configuration_source": args.config_source,
        "ssh_alias": args.ssh_alias,
        "ssh_host_supplied": args.ssh_host,
        "ssh_user_supplied": args.ssh_user_supplied,
        "ssh_key_supplied": args.ssh_key_supplied,
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
        "resolved_openssh": resolved,
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
        if args.ssh_key is not None and not args.ssh_key.is_file():
            raise SystemExit(f"SSH key does not exist: {args.ssh_key}")
        if not 1 <= args.worker_port <= 65535:
            raise SystemExit("worker port is outside the bounded TCP range")
        resolved: dict[str, object] | None = None
        if args.ssh_alias:
            resolved, alias_result = _resolve_alias(args.ssh_alias)
            if resolved is None:
                record = _diagnostic_record(args, outcome="UNKNOWN", blocker="SSH_ALIAS_CONFIGURATION_UNAVAILABLE", diagnostic=alias_result.stderr or alias_result.stdout)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(record, sort_keys=True))
                return 2
            if resolved.get("public_key_authentication") is False:
                record = _diagnostic_record(args, outcome="UNKNOWN", blocker="SSH_PUBLIC_KEY_AUTHENTICATION_DISABLED", resolved=resolved)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(record, sort_keys=True))
                return 2
            args.ssh_host = str(resolved["hostname"])
            args.ssh_user = str(resolved["user"])
            args.worker_host = args.worker_host or args.ssh_host
            destination = _alias_ssh_args(args.ssh_alias, args.ssh_key)
        else:
            destination = _ssh_args(args.ssh_host, args.ssh_user, args.ssh_key)
            args.worker_host = args.worker_host or args.ssh_host
        hostname = _run_ssh(destination, "hostname")
        if hostname.returncode != 0:
            blocker = "SSH_HOST_KEY_REJECTED" if "Host key verification failed" in hostname.stderr else "SSH_PUBLICKEY_AUTHENTICATION_FAILED"
            record = _diagnostic_record(args, outcome="UNKNOWN", blocker=blocker, diagnostic=hostname.stderr, resolved=resolved)
        else:
            observed_hostname = hostname.stdout.strip()
            facts_command = "python3 -c 'import json,platform,sys,os; print(json.dumps({\"os\":platform.system().lower(),\"os_release\":platform.release(),\"architecture\":platform.machine().lower(),\"python_implementation\":platform.python_implementation(),\"python_version\":platform.python_version(),\"cpu_count\":os.cpu_count()},sort_keys=True))'"
            facts = _run_ssh(destination, facts_command)
            observed: dict[str, Any] | None = None
            if facts.returncode == 0:
                parsed = json.loads(facts.stdout)
                if isinstance(parsed, dict):
                    observed = parsed
            matched = observed_hostname.casefold() == args.expected_hostname.casefold()
            outcome = "PASS" if facts.returncode == 0 and matched and observed is not None else "UNKNOWN"
            record = _diagnostic_record(args, outcome=outcome, observed_hostname=observed_hostname, observed=observed, blocker=None if outcome == "PASS" else "LINUX_PREFLIGHT_FACTS_UNAVAILABLE", diagnostic=facts.stderr, resolved=resolved)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(record, sort_keys=True))
        return 0 if record["outcome"] == "PASS" else 2
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"outcome": "UNKNOWN", "error": type(exc).__name__ + ": " + str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
