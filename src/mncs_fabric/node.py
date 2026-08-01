from __future__ import annotations

import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import file_identity
from .canonical import attach_identity, sha256_identity
from .models import NODE_SCHEMA

_TOOL_NAMES = ("git", "gcc", "clang", "make", "rustc", "cargo", "podman", "docker", "pwsh", "powershell")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def collect_node_capabilities(machine_label: str) -> dict[str, Any]:
    if not machine_label or len(machine_label) > 200:
        raise ValueError("machine_label must be a non-empty bounded string")
    tools = {name: path for name in _TOOL_NAMES if (path := shutil.which(name)) is not None}
    executable = Path(sys.executable).resolve()
    try:
        executable_size, executable_identity = file_identity(executable)
    except OSError:
        executable_size, executable_identity = None, None
    stable = {
        "machine_label": machine_label,
        "os": platform.system().lower(),
        "os_release": platform.release(),
        "architecture": platform.machine().lower(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable": str(executable),
        "python_executable_size": executable_size,
        "python_executable_identity": executable_identity,
        "cpu_count": os.cpu_count(),
        "tools": tools,
    }
    record = {
        "schema_version": NODE_SCHEMA,
        **stable,
        "node_fingerprint": sha256_identity(stable),
        "captured_at": utc_now(),
    }
    return attach_identity(record, "record_id")


def capability_names(record: dict[str, Any]) -> set[str]:
    values = {
        f"os:{record['os']}",
        f"arch:{record['architecture']}",
        "python",
        f"python:{record['python_version'].split('.')[0]}.{record['python_version'].split('.')[1]}",
    }
    values.update(f"tool:{name}" for name in record.get("tools", {}))
    return values
