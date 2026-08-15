"""Platform-neutral Fabric worker supervisor.

The management plane talks to this interface.  Adapters cover the two
deployments that actually exist: systemd-user on Linux and a current-user
Windows Scheduled Task.  The worker process never kills itself; it stages
work and asks the supervisor to restart.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .canonical import attach_identity, verify_identity
from .errors import ValidationError
from .inventory import first_line, run_argv
from .node import utc_now

SUPERVISOR_SCHEMA = "mncs-fabric.worker-supervisor.v0.1"
SUPERVISOR_KINDS = frozenset({
    "systemd-user",
    "windows-scheduled-task",
    "windows-service",
    "process",
    "absent",
})
COMPATIBILITY_STATES = frozenset({"current", "upgradeable", "bootstrap-required", "unsupported"})
STAGE_REQUEST_NAME = "upgrade-request.json"
MANAGEMENT_MIN_VERSION = (0, 2, 0, 21)


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def parse_fabric_version(value: str | None) -> tuple[int, int, int, str]:
    if not value:
        return (0, 0, 0, "")
    core, _, pre = value.partition("a")
    parts = core.split(".")
    try:
        numbers = [int(item) for item in parts[:3]]
        pre_number = int(pre) if pre else 10**9
    except ValueError:
        return (0, 0, 0, 0)
    while len(numbers) < 3:
        numbers.append(0)
    return (numbers[0], numbers[1], numbers[2], pre_number)


def classify_worker_version(version: str | None) -> str:
    parsed = parse_fabric_version(version)
    if parsed >= MANAGEMENT_MIN_VERSION:
        return "current"
    if parsed >= (0, 2, 0, 6):
        return "upgradeable"
    if parsed > (0, 0, 0, ""):
        return "bootstrap-required"
    return "unsupported"


def default_stage_dir() -> Path:
    if os.name == "nt":
        root = Path.home() / "mncs-fabric-worker" / "state" / "upgrade"
    else:
        linux = Path.home() / "mncs-fabric-worker" / "current" / "state" / "upgrade"
        if linux.parent.is_dir():
            return linux
        root = Path.home() / ".local" / "state" / "mncs-fabric" / "upgrade"
    return root


def inspect_supervisor(*, worker_id: str) -> dict[str, Any]:
    if os.name == "nt":
        observed = _inspect_windows(worker_id)
    else:
        observed = _inspect_linux(worker_id)
    value = {
        "schema_version": SUPERVISOR_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "kind": observed["kind"],
        "unit": observed.get("unit"),
        "state": observed.get("state") or "unknown",
        "restart_policy": observed.get("restart_policy"),
        "python_executable": observed.get("python_executable"),
        "package_version": observed.get("package_version"),
        "stage_dir": str(default_stage_dir()),
        "captured_at": utc_now(),
        "claim_boundary": "local supervisor observation; not attestation or host honesty",
    }
    return attach_identity(value, "supervisor_identity")


def validate_supervisor(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != SUPERVISOR_SCHEMA:
        raise ValidationError("unsupported supervisor schema")
    required = {
        "schema_version", "worker_identity", "kind", "unit", "state",
        "restart_policy", "python_executable", "package_version", "stage_dir",
        "captured_at", "claim_boundary", "supervisor_identity",
    }
    if set(value) != required or not verify_identity(value, "supervisor_identity"):
        raise ValidationError("supervisor fields or identity are invalid")
    if value["kind"] not in SUPERVISOR_KINDS:
        raise ValidationError("supervisor kind is unsupported")
    return dict(value)


def _inspect_linux(worker_id: str) -> dict[str, Any]:
    units = (
        "mncs-fabric-worker.service",
        f"mncs-fabric-worker-rendezvous@{worker_id}.service",
        "mncs-fabric-worker-rendezvous.service",
    )
    for unit in units:
        show = run_argv(["systemctl", "--user", "show", unit, "--property=LoadState,ActiveState,FragmentPath,Restart"], timeout=3.0)
        if show["returncode"] != 0 or "LoadState=not-found" in show["stdout"] or "LoadState=loaded" not in show["stdout"]:
            continue
        state = "unknown"
        fragment = None
        restart = None
        for line in show["stdout"].splitlines():
            if line.startswith("ActiveState="):
                state = {"active": "running", "inactive": "stopped", "failed": "failed"}.get(line.split("=", 1)[1], line.split("=", 1)[1])
            elif line.startswith("FragmentPath="):
                fragment = line.split("=", 1)[1] or None
            elif line.startswith("Restart="):
                restart = line.split("=", 1)[1] or None
        python = _linux_python()
        return {
            "kind": "systemd-user",
            "unit": unit,
            "state": state,
            "restart_policy": restart,
            "python_executable": python,
            "package_version": _package_version(python),
            "fragment": fragment,
        }
    python = _linux_python()
    return {
        "kind": "absent" if python is None else "process",
        "unit": None,
        "state": "unknown",
        "restart_policy": None,
        "python_executable": python,
        "package_version": _package_version(python),
    }


def _linux_python() -> str | None:
    candidates = [
        Path.home() / "mncs-fabric-worker" / "current" / "venv" / "bin" / "python",
        Path.home() / ".local" / "share" / "mncs-fabric" / "venv" / "bin" / "python",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return shutil.which("python3") or sys.executable


def _inspect_windows(worker_id: str) -> dict[str, Any]:
    task_name = "MNCS-Fabric-Worker"
    queried = run_argv(["schtasks", "/Query", "/TN", task_name, "/FO", "LIST"], timeout=8.0)
    python = _windows_python()
    if queried["returncode"] == 0 and "TaskName" in (queried["stdout"] or ""):
        state = "running" if "Running" in queried["stdout"] else "ready" if "Ready" in queried["stdout"] else "unknown"
        return {
            "kind": "windows-scheduled-task",
            "unit": task_name,
            "state": state,
            "restart_policy": "on-failure",
            "python_executable": python,
            "package_version": _package_version(python),
        }
    service = run_argv(["sc", "query", "MNCSFabricWorker"], timeout=5.0)
    if service["returncode"] == 0 and "SERVICE_NAME" in (service["stdout"] or ""):
        return {
            "kind": "windows-service",
            "unit": "MNCSFabricWorker",
            "state": "running" if "RUNNING" in (service["stdout"] or "") else "stopped",
            "restart_policy": "service",
            "python_executable": python,
            "package_version": _package_version(python),
        }
    return {
        "kind": "process",
        "unit": None,
        "state": "unknown",
        "restart_policy": None,
        "python_executable": python,
        "package_version": _package_version(python),
    }


def _windows_python() -> str | None:
    candidates = [
        Path.home() / "mncs-fabric-gpu" / ".venv" / "Scripts" / "python.exe",
        Path.home() / "mncs-fabric-worker" / ".venv" / "Scripts" / "python.exe",
        Path.home() / "mncs-fabric-worker" / "venv" / "Scripts" / "python.exe",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return shutil.which("python") or sys.executable


def _package_version(python: str | None) -> str | None:
    if not python:
        return None
    probed = run_argv([python, "-c", "import mncs_fabric; print(mncs_fabric.__version__)"], timeout=8.0)
    return first_line(probed["stdout"]) if probed["returncode"] == 0 else None


def write_upgrade_request(*, source: str, version: str, stage_dir: Path | None = None) -> Path:
    directory = Path(stage_dir or default_stage_dir())
    directory.mkdir(parents=True, exist_ok=True)
    request = {
        "schema_version": "mncs-fabric.upgrade-request.v0.1",
        "source": source,
        "version": version,
        "requested_at": utc_now(),
        "previous_version": __version__,
    }
    path = directory / STAGE_REQUEST_NAME
    path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_upgrade_request(stage_dir: Path | None = None) -> dict[str, Any] | None:
    path = Path(stage_dir or default_stage_dir()) / STAGE_REQUEST_NAME
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def restart_supervisor(observation: Mapping[str, Any]) -> dict[str, Any]:
    kind = observation.get("kind")
    unit = observation.get("unit")
    if kind == "systemd-user" and unit:
        probed = run_argv(["systemctl", "--user", "restart", str(unit)], timeout=30.0)
        return {"disposition": "PASS" if probed["returncode"] == 0 else "FAIL", "detail": first_line(probed["stderr"] or probed["stdout"]) or f"restart {unit}", "stdout": probed["stdout"], "stderr": probed["stderr"]}
    if kind == "windows-scheduled-task":
        return _restart_windows_detached(observation)
    if kind == "windows-service" and unit:
        return {"disposition": "SKIPPED", "detail": "Windows service restart requires privilege", "failure_class": "PRIVILEGE_REQUIRED"}
    return {"disposition": "SKIPPED", "detail": "no supervisor is available to restart the worker", "failure_class": "UNSUPPORTED_ACTION"}


def _windows_root() -> Path:
    return Path.home() / "mncs-fabric-worker"


def _windows_launcher_script() -> Path | None:
    candidates = [
        _windows_root() / "launcher" / "windows_worker_launcher.py",
        Path(__file__).resolve().parents[2] / "scripts" / "windows_worker_launcher.py",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def _restart_windows_detached(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Restart through the detached launcher.

    ``schtasks /Run`` from a non-interactive SSH session fails for Interactive
    tasks (Last Result 1).  The launcher uses CREATE_BREAKAWAY_FROM_JOB so the
    worker outlives the management session.
    """

    if os.name != "nt":
        return {"disposition": "SKIPPED", "detail": "Windows supervisor restart is only implemented on Windows", "failure_class": "UNSUPPORTED_PLATFORM"}
    python = observation.get("python_executable") or _windows_python()
    launcher = _windows_launcher_script()
    if not python or launcher is None:
        return {"disposition": "SKIPPED", "detail": "Windows detached launcher or Python runtime is missing", "failure_class": "UNSUPPORTED_ACTION"}
    root = _windows_root()
    state = root / "state" / "launcher.json"
    flags = 0
    if os.name == "nt":
        flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
        )
    helper = [python, str(launcher), "restart", "--state", str(state), "--delay", "3", "--cwd", str(root)]
    if os.name == "nt":
        # cmd start /B is more reliable than Popen flags alone under OpenSSH jobs.
        helper = ["cmd.exe", "/c", "start", "", "/B"] + helper
    try:
        subprocess.Popen(helper, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags, start_new_session=(os.name == "posix"))
    except OSError as exc:
        return {"disposition": "FAIL", "detail": f"could not schedule detached Windows restart: {exc}", "failure_class": "SERVICE_FAILURE"}
    return {"disposition": "PASS", "detail": "scheduled detached Windows launcher restart"}


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _default_windows_worker_command(python: str, root: Path, worker_id: str) -> list[str]:
    controller_id = os.environ.get("MNCS_FABRIC_CONTROLLER_ID") or "mncs-fabric-controller"
    return [
        python, "-m", "mncs_fabric", "worker", "serve",
        "--worker-id", worker_id,
        "--controller-id", controller_id,
        "--bundle-root", str(root / "bundle-root"),
        "--state", str(root / "state" / "worker-ledger.jsonl"),
        "--trust-state", str(root / "trust" / "worker-trust.jsonl"),
        "--ca", str(root / "certs" / "ca.pem"),
        "--certificate", str(root / "certs" / "worker.pem"),
        "--key", str(root / "certs" / "worker.key"),
        "--host", "0.0.0.0",
        "--port", "7443",
        "--timeout", "30",
        "--max-requests", "100000",
        "--max-concurrent-connections", "1",
        "--graceful-shutdown-timeout", "5",
        "--bundle-cache", str(root / "bundle-cache"),
    ]


def resolve_upgrade_source(desired: str, *, stage_dir: Path | None = None) -> Path | None:
    """Resolve a staged sdist/wheel/checkout for a desired Fabric version or path."""

    if desired and Path(desired).exists():
        return Path(desired)
    directory = Path(stage_dir or default_stage_dir())
    candidates = [
        directory / f"mncs-fabric-{desired}.tar.gz",
        directory / f"mncs_fabric-{desired}.tar.gz",
        directory / "mncs-fabric.tar.gz",
        directory / "source",
    ]
    request = read_upgrade_request(directory)
    if request and request.get("source"):
        candidates.insert(0, Path(str(request["source"])))
    for path in candidates:
        if path.exists():
            return path
    return None


def apply_staged_from_disk() -> dict[str, Any]:
    """Apply a previously staged upgrade request using this interpreter."""

    request = read_upgrade_request()
    if request is None:
        return {"disposition": "NO_CHANGES", "detail": "no staged upgrade request"}
    source = resolve_upgrade_source(str(request.get("source") or ""), stage_dir=default_stage_dir())
    if source is None:
        return {"disposition": "FAIL", "failure_class": "PACKAGE_FAILURE", "detail": "staged upgrade source is missing"}
    return apply_staged_upgrade(python=sys.executable, source=str(source), previous=request.get("previous_version"))


def apply_staged_upgrade(*, python: str, source: str, previous: str | None) -> dict[str, Any]:
    if not Path(source).exists():
        return {"disposition": "FAIL", "failure_class": "PACKAGE_FAILURE", "detail": f"upgrade source does not exist: {source}"}
    probed = run_argv([python, "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", source], timeout=180.0)
    if probed["returncode"] != 0:
        return {"disposition": "FAIL", "failure_class": "PACKAGE_FAILURE", "detail": "pip install of staged Fabric source failed", "stdout": probed["stdout"], "stderr": probed["stderr"], "rollback": {"capability": "partial", "previous_version": previous}}
    return {
        "disposition": "PASS",
        "detail": f"activated staged Fabric source {source}",
        "restart_required": True,
        "stdout": probed["stdout"],
        "stderr": probed["stderr"],
        "rollback": {"capability": "partial", "previous_version": previous},
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="mncs-fabric-supervisor")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--worker-id", default="local-worker")
    sub.add_parser("apply-staged")
    restart = sub.add_parser("restart")
    restart.add_argument("--worker-id", default="local-worker")
    args = parser.parse_args(argv)
    if args.command == "inspect":
        print(json.dumps(inspect_supervisor(worker_id=args.worker_id), indent=2, sort_keys=True))
        return 0
    if args.command == "apply-staged":
        result = apply_staged_from_disk()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("disposition") in {"PASS", "NO_CHANGES"} else 1
    observation = inspect_supervisor(worker_id=args.worker_id)
    result = restart_supervisor(observation)
    print(json.dumps({"supervisor": observation, "restart": result}, indent=2, sort_keys=True))
    return 0 if result.get("disposition") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
