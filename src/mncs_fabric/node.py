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
from .topology import collect_network_topology

_TOOL_NAMES = ("git", "gcc", "clang", "make", "rustc", "cargo", "podman", "docker", "pwsh", "powershell", "mncs")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def collect_platform_facts() -> dict[str, Any]:
    """Collect classified platform facts without assuming a Fedora-like host.

    Imported lazily so ``node`` stays importable where discovery is
    unwanted; every fact is worker-observed and may be ``unknown``.
    """
    from .platform_probe import collect_platform_facts as collect

    return collect()


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
    try:
        platform_facts = collect_platform_facts()
    except Exception:
        platform_facts = {}
    record = {
        "schema_version": NODE_SCHEMA,
        **stable,
        "node_fingerprint": sha256_identity(stable),
        "network_topology": collect_network_topology(machine_label),
        "platform": platform_facts,
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
    platform_facts = record.get("platform")
    if isinstance(platform_facts, dict):
        libc = platform_facts.get("libc")
        if isinstance(libc, str) and libc not in ("", "unknown"):
            values.add(f"libc:{libc}")
        init = platform_facts.get("init")
        if isinstance(init, str) and init not in ("", "unknown"):
            values.add(f"init:{init}")
        accel = platform_facts.get("accel")
        if accel == "cuda":
            values.add("accel:cuda")
            values.add("accelerator:cuda")
            values.add(
                f"cuda:compute-{platform_facts.get('cuda_major', 0)}-{platform_facts.get('cuda_minor', 0)}"
            )
            if platform_facts.get("has_ptx"):
                values.add("compiler:ptx")
        elif isinstance(accel, str) and accel not in ("", "unknown", "none"):
            values.add(f"accel:{accel}")
        if platform_facts.get("has_ebpf"):
            values.add("kernel:ebpf")
        if platform_facts.get("has_btf"):
            values.add("kernel:btf")
        if platform_facts.get("has_wasm"):
            values.add("runtime:wasm")
        for runtime in platform_facts.get("wasm_runtimes", []) or []:
            values.add(f"runtime:{runtime}")
        for shell in platform_facts.get("shells", []) or []:
            values.add(f"shell:{shell}")
        for arch in platform_facts.get("emulated_arches", []) or []:
            values.add(f"emulation:{arch}")
    return values
