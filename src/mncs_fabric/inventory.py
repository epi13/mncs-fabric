"""Worker-observed host inventory for the Fabric management plane.

Inventory is an authenticated worker report, not attestation.  It records how
tools and runtimes are actually installed and managed instead of assuming a
fixed service manager or package path.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import __version__
from .canonical import attach_identity, canonical_json_bytes, is_sha256_identity, verify_identity
from .errors import ValidationError
from .node import utc_now

INVENTORY_SCHEMA = "mncs-fabric.worker-inventory.v0.1"
INVENTORY_CLAIM_BOUNDARY = (
    "authenticated worker-observed inventory; not attestation, honesty, "
    "continuous availability, semantic suitability, or conformance"
)
MAX_INVENTORY_BYTES = 256 * 1024
MAX_TOOLS = 64
MAX_RUNTIMES = 16
MAX_MODELS = 64
MAX_REPOS = 32
MAX_SERVICES = 32
MAX_CREDENTIALS = 16
MAX_ACCELERATORS = 16
TOOL_PROBE_TIMEOUT = 4.0
HTTP_PROBE_TIMEOUT = 3.0

TOOL_SPECS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("git", ("--version",)),
    ("gh", ("--version",)),
    ("python", ("--version",)),
    ("pip", ("--version",)),
    ("uv", ("--version",)),
    ("rustc", ("--version",)),
    ("cargo", ("--version",)),
    ("gcc", ("--version",)),
    ("clang", ("--version",)),
    ("joern", ()),
    ("forge", ("--version",)),
    ("ollama", ("--version",)),
    ("bwrap", ("--version",)),
)

UPDATE_CLASSES = frozenset({"A", "B", "C", "D", "E"})
SERVICE_MANAGERS = frozenset({
    "systemd-system",
    "systemd-user",
    "windows-service",
    "windows-scheduled-task",
    "process",
    "supervisor",
    "unknown",
    "absent",
})
INSTALL_TYPES = frozenset({
    "package",
    "pip",
    "cargo",
    "binary",
    "repository",
    "windows-package",
    "unknown",
    "absent",
})
PRESSURE = frozenset({"ok", "elevated", "critical", "unknown"})


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, field, maximum)


def _timestamp(value: object, field: str = "captured_at") -> str:
    _text(value, field, 64)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _nonnegative(value: object, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"{field} must be a non-negative integer or null")
    return value


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be a boolean")
    return value


def run_argv(argv: list[str], *, timeout: float = TOOL_PROBE_TIMEOUT) -> dict[str, Any]:
    """Run a fixed argv without a shell and return a bounded observation."""

    if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
        raise ValidationError("argv must be a non-empty list of bounded strings")
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "not-found", "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timeout", "timed_out": True}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc)[:256], "timed_out": False}
    return {
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[:4096],
        "stderr": (completed.stderr or "")[:4096],
        "timed_out": False,
    }


def first_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:256]
    return None


def redact_text(value: str) -> str:
    """Remove common credential material from captured tool output."""

    import re

    redacted = value
    redacted = re.sub(r"ghp_[A-Za-z0-9_]{20,}", "[redacted-github-token]", redacted)
    redacted = re.sub(r"gho_[A-Za-z0-9_]{20,}", "[redacted-github-token]", redacted)
    redacted = re.sub(r"github_pat_[A-Za-z0-9_]{20,}", "[redacted-github-token]", redacted)
    redacted = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[redacted-private-key]", redacted, flags=re.S)
    redacted = re.sub(r"(?i)(password|token|secret|authorization)=(\S+)", r"\1=[redacted]", redacted)
    return redacted[:4096]


def _os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, raw = line.split("=", 1)
            values[key] = raw.strip().strip('"')[:128]
    except (OSError, UnicodeError):
        return {}
    return values


def _disk_usage(path: str = "/") -> tuple[int | None, int | None]:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None, None
    return int(usage.total), int(usage.free)


def _load_average() -> float | None:
    getter = getattr(os, "getloadavg", None)
    if getter is None:
        return None
    try:
        return float(getter()[0])
    except (OSError, ValueError):
        return None


def _pending_reboot() -> bool | None:
    if platform.system().lower() != "linux":
        return None
    if Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists():
        return True
    marker = Path("/var/run/reboot-required.pkgs")
    if marker.exists():
        return True
    return False


def _hostname() -> str:
    try:
        return socket.gethostname()[:128] or "unknown-host"
    except OSError:
        return "unknown-host"


def _python_tool() -> dict[str, Any]:
    executable = Path(sys.executable).resolve()
    return _tool_record(
        name="python",
        present=True,
        path=str(executable),
        version=platform.python_version(),
        detail=platform.python_implementation(),
    )


def _tool_record(*, name: str, present: bool, path: str | None, version: str | None, detail: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "present": present,
        "path": path,
        "version": version,
        "detail": detail,
    }


def _windows_extra_paths(name: str) -> list[str]:
    if os.name != "nt":
        return []
    home = Path.home()
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidates = {
        "git": [
            program_files / "Git" / "cmd" / "git.exe",
            home / "AppData" / "Local" / "Programs" / "Git" / "cmd" / "git.exe",
        ],
        "gh": [
            program_files / "GitHub CLI" / "gh.exe",
            home / "AppData" / "Local" / "Programs" / "GitHub CLI" / "gh.exe",
        ],
        "ollama": [
            program_files / "Ollama" / "ollama.exe",
            home / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe",
        ],
    }
    return [str(path) for path in candidates.get(name, []) if path.is_file()]


def _probe_tool(name: str, version_args: tuple[str, ...]) -> dict[str, Any]:
    if name == "python":
        path = shutil.which("python") or shutil.which("python3") or sys.executable
    else:
        path = shutil.which(name) or next(iter(_windows_extra_paths(name)), None)
    if not path:
        return _tool_record(name=name, present=False, path=None, version=None, detail=None)
    if not version_args:
        return _tool_record(name=name, present=True, path=path, version=None, detail="present-unversioned")
    result = run_argv([path, *version_args])
    version = first_line(result["stdout"]) or first_line(result["stderr"])
    detail = None
    if result["timed_out"]:
        detail = "version-probe-timeout"
    elif result["returncode"] not in {0, None} and version is None:
        detail = "version-probe-failed"
    return _tool_record(name=name, present=True, path=path, version=version, detail=detail)


def collect_tools() -> list[dict[str, Any]]:
    tools = [_python_tool()]
    seen = {"python"}
    for name, args in TOOL_SPECS:
        if name in seen:
            continue
        tools.append(_probe_tool(name, args))
        seen.add(name)
    pip = shutil.which("pip") or shutil.which("pip3")
    if not any(item["name"] == "pip" and item["present"] for item in tools) and pip:
        tools = [item for item in tools if item["name"] != "pip"]
        tools.append(_probe_tool("pip", ("--version",)))
    tools.sort(key=lambda item: item["name"])
    return tools[:MAX_TOOLS]


def _systemctl(args: list[str], *, user: bool) -> dict[str, Any]:
    binary = shutil.which("systemctl")
    if not binary:
        return {"returncode": None, "stdout": "", "stderr": "systemctl-absent", "timed_out": False}
    argv = [binary, "--user", *args] if user else [binary, *args]
    return run_argv(argv, timeout=3.0)


def _windows_scheduled_task(name: str) -> dict[str, Any] | None:
    if platform.system().lower() != "windows":
        return None
    task_name = "MNCS-Fabric-Worker" if name in {"fabric-worker", "mncs-fabric-worker"} else name
    queried = run_argv(["schtasks", "/Query", "/TN", task_name, "/FO", "LIST"], timeout=8.0)
    if queried["returncode"] != 0 or "TaskName" not in (queried["stdout"] or ""):
        return None
    output = queried["stdout"] or ""
    state = "unknown"
    if "Status:" in output:
        for line in output.splitlines():
            if line.strip().startswith("Status:"):
                raw = line.split(":", 1)[1].strip().lower()
                state = {"ready": "ready", "running": "running"}.get(raw, raw or "unknown")
                break
    if _process_listening(7443):
        state = "running"
    return {
        "name": name,
        "present": True,
        "manager": "windows-scheduled-task",
        "unit": task_name,
        "state": state,
        "install_type": "windows-package",
    }


def _windows_service(name: str) -> dict[str, Any] | None:
    if platform.system().lower() != "windows":
        return None
    sc = shutil.which("sc")
    if not sc:
        return None
    result = run_argv([sc, "query", name], timeout=3.0)
    output = (result["stdout"] or "") + "\n" + (result["stderr"] or "")
    if result["returncode"] not in {0} or "FAILED" in output:
        return None
    state = "unknown"
    for line in output.splitlines():
        if "RUNNING" in line:
            state = "running"
        elif "STOPPED" in line:
            state = "stopped"
    return {
        "name": name,
        "present": True,
        "manager": "windows-service",
        "unit": name,
        "state": state,
        "install_type": "windows-package",
    }


def _process_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


def discover_service(name: str, *, units: tuple[str, ...] | None = None, listen_port: int | None = None) -> dict[str, Any]:
    """Discover how a named service is installed without assuming systemd."""

    candidates = units or (name, f"{name}.service")
    for unit in candidates:
        system = _systemctl(["show", unit, "--property=LoadState,ActiveState,FragmentPath,Id"], user=False)
        if system["returncode"] == 0 and "LoadState=not-found" not in system["stdout"] and "LoadState=loaded" in system["stdout"]:
            state = "unknown"
            for line in system["stdout"].splitlines():
                if line.startswith("ActiveState="):
                    mapped = line.split("=", 1)[1].strip()
                    state = {"active": "running", "activating": "running", "reloading": "running", "inactive": "stopped", "failed": "failed"}.get(mapped, mapped)
            return {
                "name": name,
                "present": True,
                "manager": "systemd-system",
                "unit": unit,
                "state": state,
                "install_type": "package",
            }
        user = _systemctl(["show", unit, "--property=LoadState,ActiveState,FragmentPath,Id"], user=True)
        if user["returncode"] == 0 and "LoadState=not-found" not in user["stdout"] and "LoadState=loaded" in user["stdout"]:
            state = "unknown"
            for line in user["stdout"].splitlines():
                if line.startswith("ActiveState="):
                    mapped = line.split("=", 1)[1].strip()
                    state = {"active": "running", "activating": "running", "reloading": "running", "inactive": "stopped", "failed": "failed"}.get(mapped, mapped)
            return {
                "name": name,
                "present": True,
                "manager": "systemd-user",
                "unit": unit,
                "state": state,
                "install_type": "package",
            }
    windows = _windows_service(name)
    if windows is not None:
        return windows
    scheduled = _windows_scheduled_task(name)
    if scheduled is not None:
        return scheduled
    if listen_port is not None and _process_listening(listen_port):
        return {
            "name": name,
            "present": True,
            "manager": "process",
            "unit": f"127.0.0.1:{listen_port}",
            "state": "running",
            "install_type": "unknown",
        }
    if shutil.which(name):
        return {
            "name": name,
            "present": True,
            "manager": "unknown",
            "unit": None,
            "state": "unknown",
            "install_type": "binary",
        }
    return {
        "name": name,
        "present": False,
        "manager": "absent",
        "unit": None,
        "state": "absent",
        "install_type": "absent",
    }


def _http_json(url: str, *, timeout: float = HTTP_PROBE_TIMEOUT) -> dict[str, Any] | None:
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json", "User-Agent": "mncs-fabric-inventory"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(256 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def collect_ollama_models(endpoint: str = "http://127.0.0.1:11434") -> tuple[list[dict[str, Any]], str | None]:
    payload = _http_json(endpoint.rstrip("/") + "/api/tags")
    if payload is None:
        return [], None
    models: list[dict[str, Any]] = []
    raw_models = payload.get("models")
    if not isinstance(raw_models, list):
        return [], endpoint
    for item in raw_models[:MAX_MODELS]:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name") or item.get("model")
        if not isinstance(name, str) or not name:
            continue
        details = item.get("details") if isinstance(item.get("details"), Mapping) else {}
        size = item.get("size")
        models.append(
            {
                "name": name[:256],
                "digest": str(item["digest"])[:128] if isinstance(item.get("digest"), str) else None,
                "size_bytes": size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else None,
                "family": str(details["family"])[:64] if isinstance(details.get("family"), str) else None,
                "parameter_size": str(details["parameter_size"])[:64] if isinstance(details.get("parameter_size"), str) else None,
                "quantization": str(details["quantization_level"])[:64] if isinstance(details.get("quantization_level"), str) else None,
            }
        )
    models.sort(key=lambda item: item["name"].casefold())
    return models, endpoint


def collect_runtimes() -> list[dict[str, Any]]:
    service = discover_service("ollama", units=("ollama.service", "ollama"), listen_port=11434)
    models, endpoint = collect_ollama_models()
    version = None
    path = shutil.which("ollama")
    if path:
        probed = run_argv([path, "--version"])
        version = first_line(probed["stdout"]) or first_line(probed["stderr"])
    reachable = endpoint is not None
    if reachable and service["manager"] == "absent":
        service = {
            "name": "ollama",
            "present": True,
            "manager": "process",
            "unit": "127.0.0.1:11434",
            "state": "running",
            "install_type": "unknown",
        }
    runtime = {
        "name": "ollama",
        "present": bool(path) or reachable or service["present"],
        "install_type": service["install_type"] if service["present"] else ("binary" if path else "absent"),
        "service_type": service["manager"],
        "endpoint": endpoint or ("http://127.0.0.1:11434" if path or service["present"] else None),
        "version": version,
        "reachable": reachable,
        "models": models,
    }
    return [runtime]


def collect_services(*, worker_id: str) -> list[dict[str, Any]]:
    fabric_units = (
        f"mncs-fabric-worker-rendezvous@{worker_id}.service",
        "mncs-fabric-worker-rendezvous.service",
        "mncs-fabric-worker.service",
        "fabric-worker.service",
    )
    services = [
        discover_service("fabric-worker", units=fabric_units, listen_port=7443),
        discover_service("ollama", units=("ollama.service", "ollama"), listen_port=11434),
        discover_service("mncs-fabric-controller", units=("mncs-fabric-controller.service",)),
    ]
    return services[:MAX_SERVICES]


def collect_credentials() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    gh = shutil.which("gh")
    if gh:
        probed = run_argv([gh, "auth", "status"], timeout=5.0)
        output = redact_text((probed["stdout"] or "") + "\n" + (probed["stderr"] or ""))
        available = probed["returncode"] == 0 and "Logged in" in output
        detail = "authenticated" if available else "unauthenticated-or-unavailable"
        records.append({"name": "github-cli", "available": available, "detail": detail})
    else:
        records.append({"name": "github-cli", "available": False, "detail": "gh-absent"})
    joern = shutil.which("joern")
    records.append({"name": "joern", "available": joern is not None, "detail": "executable-present" if joern else "absent"})
    forge = shutil.which("forge") or shutil.which("mncs-forge")
    records.append({"name": "forge", "available": forge is not None, "detail": "executable-present" if forge else "absent"})
    return records[:MAX_CREDENTIALS]


def collect_repositories(paths: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    configured = dict(paths or {})
    fabric_root = Path(__file__).resolve().parents[2]
    if (fabric_root / ".git").exists() and "mncs-fabric" not in configured:
        configured["mncs-fabric"] = str(fabric_root)
    for name, raw_path in list(configured.items())[:MAX_REPOS]:
        path = Path(raw_path)
        git = shutil.which("git")
        if not git or not path.exists():
            records.append(
                {
                    "name": name[:128],
                    "path": str(path)[:512],
                    "branch": None,
                    "commit": None,
                    "dirty": None,
                    "remote": None,
                }
            )
            continue
        branch = first_line(run_argv([git, "-C", str(path), "rev-parse", "--abbrev-ref", "HEAD"])["stdout"])
        commit = first_line(run_argv([git, "-C", str(path), "rev-parse", "HEAD"])["stdout"])
        status = run_argv([git, "-C", str(path), "status", "--porcelain"])
        remote = first_line(run_argv([git, "-C", str(path), "rev-parse", "@{upstream}"])["stdout"])
        records.append(
            {
                "name": name[:128],
                "path": str(path)[:512],
                "branch": branch,
                "commit": commit,
                "dirty": bool(status["stdout"].strip()) if status["returncode"] == 0 else None,
                "remote": remote,
            }
        )
    return records


def _package_version(module_name: str) -> str | None:
    try:
        module = __import__(module_name)
    except Exception:
        return None
    version = getattr(module, "__version__", None)
    return str(version)[:64] if isinstance(version, str) and version else "present"


def _pressure(used: int | None, total: int | None) -> str:
    if used is None or total is None or total <= 0:
        return "unknown"
    ratio = used / total
    if ratio >= 0.95:
        return "critical"
    if ratio >= 0.85:
        return "elevated"
    return "ok"


def collect_identity(worker_id: str) -> dict[str, Any]:
    release = _os_release()
    system = platform.system().lower()
    return {
        "hostname": _hostname(),
        "platform": system,
        "os": system,
        "distribution": release.get("ID") or (system if system == "windows" else None),
        "os_version": release.get("VERSION_ID") or platform.version()[:128],
        "kernel": platform.release()[:128],
        "architecture": platform.machine().lower()[:64],
    }


def collect_hardware(resource_snapshot: Mapping[str, Any] | None = None) -> dict[str, Any]:
    snapshot = dict(resource_snapshot or {})
    total, free = _disk_usage()
    ram_total = snapshot.get("host_memory_total_bytes")
    ram_available = snapshot.get("host_memory_available_bytes")
    accelerators = []
    for item in snapshot.get("accelerators") or []:
        if not isinstance(item, Mapping):
            continue
        accelerators.append(
            {
                "index": item.get("index"),
                "name": item.get("device_name"),
                "backend": item.get("backend"),
                "total_memory_bytes": item.get("total_memory_bytes"),
                "free_memory_bytes": item.get("free_memory_bytes"),
            }
        )
        if len(accelerators) >= MAX_ACCELERATORS:
            break
    return {
        "cpu_count": snapshot.get("cpu_logical_count") if snapshot.get("cpu_logical_count") is not None else os.cpu_count(),
        "ram_bytes": ram_total if isinstance(ram_total, int) else None,
        "ram_available_bytes": ram_available if isinstance(ram_available, int) else None,
        "disk_bytes": total,
        "disk_available_bytes": free,
        "accelerators": accelerators,
    }


def collect_health(hardware: Mapping[str, Any], *, active_jobs: int = 0) -> dict[str, Any]:
    ram_total = hardware.get("ram_bytes")
    ram_available = hardware.get("ram_available_bytes")
    disk_total = hardware.get("disk_bytes")
    disk_free = hardware.get("disk_available_bytes")
    ram_used = None
    if isinstance(ram_total, int) and isinstance(ram_available, int):
        ram_used = max(0, ram_total - ram_available)
    disk_used = None
    if isinstance(disk_total, int) and isinstance(disk_free, int):
        disk_used = max(0, disk_total - disk_free)
    pending = _pending_reboot()
    return {
        "load_1m": _load_average(),
        "ram_pressure": _pressure(ram_used, ram_total if isinstance(ram_total, int) else None),
        "disk_pressure": _pressure(disk_used, disk_total if isinstance(disk_total, int) else None),
        "pending_reboot": pending,
        "active_jobs": active_jobs,
        "maintenance_eligible": active_jobs == 0 and (pending is not True),
    }


def collect_worker_inventory(
    worker_id: str,
    *,
    resource_snapshot: Mapping[str, Any] | None = None,
    repository_paths: Mapping[str, str] | None = None,
    active_jobs: int = 0,
    captured_at: str | None = None,
    harness_version: str | None = None,
) -> dict[str, Any]:
    """Collect a normalized inventory from the local worker process."""

    identity = collect_identity(worker_id)
    if resource_snapshot is None:
        from .resources import capture_resource_snapshot

        resource_snapshot = capture_resource_snapshot(worker_id)
    hardware = collect_hardware(resource_snapshot)
    tools = collect_tools()
    runtimes = collect_runtimes()
    services = collect_services(worker_id=worker_id)
    repositories = collect_repositories(repository_paths)
    credentials = collect_credentials()
    health = collect_health(hardware, active_jobs=active_jobs)
    detected_harness = harness_version or _package_version("epi13_local_harness") or _package_version("mncs_harness")
    fabric = {
        "worker_version": __version__,
        "protocol_version": "mncs-fabric.protocol.v0.1",
        "harness_version": detected_harness,
        "agent_version": __version__,
        "python_executable": str(Path(sys.executable).resolve())[:512],
    }
    return build_worker_inventory(
        worker_id=worker_id,
        identity=identity,
        hardware=hardware,
        fabric=fabric,
        tools=tools,
        runtimes=runtimes,
        repositories=repositories,
        services=services,
        health=health,
        credentials=credentials,
        captured_at=captured_at,
    )


def _validate_tool(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "present", "path", "version", "detail"}:
        raise ValidationError("inventory tool fields are invalid")
    return {
        "name": _text(value["name"], "tools.name", 64),
        "present": _bool(value["present"], "tools.present"),
        "path": _optional_text(value["path"], "tools.path", 512),
        "version": _optional_text(value["version"], "tools.version", 256),
        "detail": _optional_text(value["detail"], "tools.detail", 256),
    }


def _validate_model(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "digest", "size_bytes", "family", "parameter_size", "quantization"}:
        raise ValidationError("inventory model fields are invalid")
    return {
        "name": _text(value["name"], "models.name", 256),
        "digest": _optional_text(value["digest"], "models.digest", 128),
        "size_bytes": _nonnegative(value["size_bytes"], "models.size_bytes"),
        "family": _optional_text(value["family"], "models.family", 64),
        "parameter_size": _optional_text(value["parameter_size"], "models.parameter_size", 64),
        "quantization": _optional_text(value["quantization"], "models.quantization", 64),
    }


def _validate_runtime(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "present", "install_type", "service_type", "endpoint", "version", "reachable", "models"}:
        raise ValidationError("inventory runtime fields are invalid")
    if value["install_type"] not in INSTALL_TYPES:
        raise ValidationError("inventory runtime install_type is unsupported")
    if value["service_type"] not in SERVICE_MANAGERS:
        raise ValidationError("inventory runtime service_type is unsupported")
    models = value["models"]
    if not isinstance(models, list) or len(models) > MAX_MODELS:
        raise ValidationError("inventory runtime models are invalid")
    return {
        "name": _text(value["name"], "runtimes.name", 64),
        "present": _bool(value["present"], "runtimes.present"),
        "install_type": value["install_type"],
        "service_type": value["service_type"],
        "endpoint": _optional_text(value["endpoint"], "runtimes.endpoint", 256),
        "version": _optional_text(value["version"], "runtimes.version", 256),
        "reachable": _bool(value["reachable"], "runtimes.reachable"),
        "models": [_validate_model(item) for item in models],
    }


def _validate_repo(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "path", "branch", "commit", "dirty", "remote"}:
        raise ValidationError("inventory repository fields are invalid")
    if value["dirty"] is not None and not isinstance(value["dirty"], bool):
        raise ValidationError("inventory repository dirty flag is invalid")
    return {
        "name": _text(value["name"], "repositories.name", 128),
        "path": _text(value["path"], "repositories.path", 512),
        "branch": _optional_text(value["branch"], "repositories.branch", 256),
        "commit": _optional_text(value["commit"], "repositories.commit", 128),
        "dirty": value["dirty"],
        "remote": _optional_text(value["remote"], "repositories.remote", 256),
    }


def _validate_service(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "present", "manager", "unit", "state", "install_type"}:
        raise ValidationError("inventory service fields are invalid")
    if value["manager"] not in SERVICE_MANAGERS:
        raise ValidationError("inventory service manager is unsupported")
    if value["install_type"] not in INSTALL_TYPES:
        raise ValidationError("inventory service install_type is unsupported")
    return {
        "name": _text(value["name"], "services.name", 128),
        "present": _bool(value["present"], "services.present"),
        "manager": value["manager"],
        "unit": _optional_text(value["unit"], "services.unit", 256),
        "state": _text(value["state"], "services.state", 64),
        "install_type": value["install_type"],
    }


def _validate_credential(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"name", "available", "detail"}:
        raise ValidationError("inventory credential fields are invalid")
    return {
        "name": _text(value["name"], "credentials.name", 64),
        "available": _bool(value["available"], "credentials.available"),
        "detail": _optional_text(value["detail"], "credentials.detail", 256),
    }


def _validate_accelerator(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"index", "name", "backend", "total_memory_bytes", "free_memory_bytes"}:
        raise ValidationError("inventory accelerator fields are invalid")
    if value["index"] is not None and (not isinstance(value["index"], int) or isinstance(value["index"], bool) or value["index"] < 0):
        raise ValidationError("inventory accelerator index is invalid")
    return {
        "index": value["index"],
        "name": _optional_text(value["name"], "accelerators.name", 256),
        "backend": _optional_text(value["backend"], "accelerators.backend", 64),
        "total_memory_bytes": _nonnegative(value["total_memory_bytes"], "accelerators.total_memory_bytes"),
        "free_memory_bytes": _nonnegative(value["free_memory_bytes"], "accelerators.free_memory_bytes"),
    }


def _validate_identity(value: object) -> dict[str, Any]:
    required = {"hostname", "platform", "os", "distribution", "os_version", "kernel", "architecture"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError("inventory identity fields are invalid")
    return {
        "hostname": _text(value["hostname"], "identity.hostname", 128),
        "platform": _text(value["platform"], "identity.platform", 32),
        "os": _text(value["os"], "identity.os", 32),
        "distribution": _optional_text(value["distribution"], "identity.distribution", 64),
        "os_version": _optional_text(value["os_version"], "identity.os_version", 128),
        "kernel": _optional_text(value["kernel"], "identity.kernel", 128),
        "architecture": _text(value["architecture"], "identity.architecture", 64),
    }


def _validate_hardware(value: object) -> dict[str, Any]:
    required = {"cpu_count", "ram_bytes", "ram_available_bytes", "disk_bytes", "disk_available_bytes", "accelerators"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError("inventory hardware fields are invalid")
    accelerators = value["accelerators"]
    if not isinstance(accelerators, list) or len(accelerators) > MAX_ACCELERATORS:
        raise ValidationError("inventory accelerators are invalid")
    cpu = value["cpu_count"]
    if cpu is not None and (not isinstance(cpu, int) or isinstance(cpu, bool) or cpu < 1):
        raise ValidationError("inventory cpu_count is invalid")
    return {
        "cpu_count": cpu,
        "ram_bytes": _nonnegative(value["ram_bytes"], "hardware.ram_bytes"),
        "ram_available_bytes": _nonnegative(value["ram_available_bytes"], "hardware.ram_available_bytes"),
        "disk_bytes": _nonnegative(value["disk_bytes"], "hardware.disk_bytes"),
        "disk_available_bytes": _nonnegative(value["disk_available_bytes"], "hardware.disk_available_bytes"),
        "accelerators": [_validate_accelerator(item) for item in accelerators],
    }


def _validate_fabric(value: object) -> dict[str, Any]:
    required = {"worker_version", "protocol_version", "harness_version", "agent_version", "python_executable"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError("inventory fabric fields are invalid")
    return {
        "worker_version": _text(value["worker_version"], "fabric.worker_version", 64),
        "protocol_version": _text(value["protocol_version"], "fabric.protocol_version", 64),
        "harness_version": _optional_text(value["harness_version"], "fabric.harness_version", 64),
        "agent_version": _optional_text(value["agent_version"], "fabric.agent_version", 64),
        "python_executable": _text(value["python_executable"], "fabric.python_executable", 512),
    }


def _validate_health(value: object) -> dict[str, Any]:
    required = {"load_1m", "ram_pressure", "disk_pressure", "pending_reboot", "active_jobs", "maintenance_eligible"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError("inventory health fields are invalid")
    if value["ram_pressure"] not in PRESSURE or value["disk_pressure"] not in PRESSURE:
        raise ValidationError("inventory health pressure is invalid")
    load = value["load_1m"]
    if load is not None and (not isinstance(load, (int, float)) or isinstance(load, bool) or load < 0):
        raise ValidationError("inventory load_1m is invalid")
    if value["pending_reboot"] is not None and not isinstance(value["pending_reboot"], bool):
        raise ValidationError("inventory pending_reboot is invalid")
    jobs = value["active_jobs"]
    if not isinstance(jobs, int) or isinstance(jobs, bool) or jobs < 0 or jobs > 1024:
        raise ValidationError("inventory active_jobs is invalid")
    return {
        "load_1m": float(load) if isinstance(load, (int, float)) and not isinstance(load, bool) else None,
        "ram_pressure": value["ram_pressure"],
        "disk_pressure": value["disk_pressure"],
        "pending_reboot": value["pending_reboot"],
        "active_jobs": jobs,
        "maintenance_eligible": _bool(value["maintenance_eligible"], "health.maintenance_eligible"),
    }


def build_worker_inventory(
    *,
    worker_id: str,
    identity: Mapping[str, Any],
    hardware: Mapping[str, Any],
    fabric: Mapping[str, Any],
    tools: list[Mapping[str, Any]],
    runtimes: list[Mapping[str, Any]],
    repositories: list[Mapping[str, Any]],
    services: list[Mapping[str, Any]],
    health: Mapping[str, Any],
    credentials: list[Mapping[str, Any]],
    captured_at: str | None = None,
) -> dict[str, Any]:
    if len(tools) > MAX_TOOLS or len(runtimes) > MAX_RUNTIMES or len(repositories) > MAX_REPOS or len(services) > MAX_SERVICES or len(credentials) > MAX_CREDENTIALS:
        raise ValidationError("inventory exceeds a collection bound")
    value: dict[str, Any] = {
        "schema_version": INVENTORY_SCHEMA,
        "worker_identity": _text(worker_id, "worker_identity"),
        "captured_at": _timestamp(captured_at or utc_now()),
        "observation_source": "worker-observed",
        "claim_boundary": INVENTORY_CLAIM_BOUNDARY,
        "identity": _validate_identity(dict(identity)),
        "hardware": _validate_hardware(dict(hardware)),
        "fabric": _validate_fabric(dict(fabric)),
        "tools": [_validate_tool(dict(item)) for item in tools],
        "runtimes": [_validate_runtime(dict(item)) for item in runtimes],
        "repositories": [_validate_repo(dict(item)) for item in repositories],
        "services": [_validate_service(dict(item)) for item in services],
        "health": _validate_health(dict(health)),
        "credentials": [_validate_credential(dict(item)) for item in credentials],
    }
    observed = attach_identity(value, "inventory_identity")
    if len(canonical_json_bytes(observed)) > MAX_INVENTORY_BYTES:
        raise ValidationError("worker inventory exceeds the encoded-size bound")
    return observed


def validate_worker_inventory(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != INVENTORY_SCHEMA:
        raise ValidationError("unsupported worker inventory schema")
    required = {
        "schema_version", "worker_identity", "captured_at", "observation_source",
        "claim_boundary", "identity", "hardware", "fabric", "tools", "runtimes",
        "repositories", "services", "health", "credentials", "inventory_identity",
    }
    if set(value) != required or not verify_identity(value, "inventory_identity"):
        raise ValidationError("worker inventory fields or identity are invalid")
    if len(canonical_json_bytes(value)) > MAX_INVENTORY_BYTES:
        raise ValidationError("worker inventory exceeds the encoded-size bound")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("worker inventory is bound to another worker")
    _timestamp(value["captured_at"])
    if value["observation_source"] != "worker-observed":
        raise ValidationError("worker inventory must identify its observation source")
    _text(value["claim_boundary"], "claim_boundary", 512)
    rebuilt = build_worker_inventory(
        worker_id=worker_id,
        identity=value["identity"],
        hardware=value["hardware"],
        fabric=value["fabric"],
        tools=value["tools"],
        runtimes=value["runtimes"],
        repositories=value["repositories"],
        services=value["services"],
        health=value["health"],
        credentials=value["credentials"],
        captured_at=value["captured_at"],
    )
    if rebuilt != value:
        raise ValidationError("worker inventory is not canonically normalized")
    return dict(value)


def inventory_tool(inventory: Mapping[str, Any], name: str) -> dict[str, Any] | None:
    for item in inventory.get("tools", []):
        if isinstance(item, Mapping) and item.get("name") == name:
            return dict(item)
    return None


def inventory_runtime(inventory: Mapping[str, Any], name: str) -> dict[str, Any] | None:
    for item in inventory.get("runtimes", []):
        if isinstance(item, Mapping) and item.get("name") == name:
            return dict(item)
    return None


def inventory_service(inventory: Mapping[str, Any], name: str) -> dict[str, Any] | None:
    for item in inventory.get("services", []):
        if isinstance(item, Mapping) and item.get("name") == name:
            return dict(item)
    return None


Collector = Callable[[str], dict[str, Any]]
