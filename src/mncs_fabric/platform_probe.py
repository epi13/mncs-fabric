"""Worker-observed platform facts beyond the historic node record.

These probes extend ``node.collect_node_capabilities`` with the
environment dimensions capability resolution needs: libc, init system,
available shells, kernel eBPF/BTF support, NVIDIA/CUDA compute
capability, WASM runtimes, and machine emulation. Every probe is bounded
(fixed argv, no shell, short timeout) and honest: anything unobservable
is reported as unknown or absent, never guessed from the hostname.

Diversity is evidence: on a minimal worker (Alpine/musl/BusyBox/OpenRC,
NixOS, Windows, ARM) the probes report what is actually there. Callers
must not install packages or create shim paths merely to make a worker
look like Fedora; the workload declaration, stdlib, or backend is the
correct place to fix a bad assumption.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

PROBE_TIMEOUT = 4.0
_WASM_RUNTIMES = ("wasmtime", "wasmer", "wasm3", "wasmedge")
_QEMU_ARCHES = ("riscv64", "aarch64", "x86_64", "arm")
_SHELLS = ("bash", "sh", "ash", "dash", "zsh", "fish", "pwsh", "powershell")


def _run(argv: list[str], *, timeout: float = PROBE_TIMEOUT) -> str:
    try:
        completed = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout, shell=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return ((completed.stdout or "") + "\n" + (completed.stderr or ""))[:2048]


def probe_libc() -> dict[str, Any]:
    """Classify the C library without assuming GNU."""
    if os.name == "nt":
        return {"libc": "win-crt", "detail": "windows-crt"}
    text = _run(["ldd", "--version"])
    lowered = text.lower()
    if "musl" in lowered:
        return {"libc": "musl", "detail": (text.splitlines() or ["musl"])[0][:128]}
    if "glibc" in lowered or "gnu libc" in lowered:
        version: str | None = None
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
        if match:
            version = match.group(1)
        getconf = _run(["getconf", "GNU_LIBC_VERSION"]).strip().split()
        detail = getconf[-1] if getconf else ((text.splitlines() or ["glibc"])[0][:128])
        return {"libc": "gnu", "detail": detail[:128], "version": version}
    return {"libc": "unknown", "detail": "unobserved"}


def probe_init() -> dict[str, Any]:
    """Classify the init/service manager without assuming systemd."""
    if os.name == "nt" or platform.system().lower() == "windows":
        return {"init": "win-service", "detail": "windows-service-manager"}
    if Path("/run/systemd/system/").is_dir():
        return {"init": "systemd", "detail": "systemd-runtime-dir-present"}
    try:
        comm = Path("/proc/1/comm").read_text(encoding="utf-8").strip().lower()
    except (OSError, UnicodeError):
        comm = ""
    if comm == "systemd":
        return {"init": "systemd", "detail": "pid-1-systemd"}
    if "openrc" in comm or Path("/run/openrc/").exists():
        return {"init": "openrc", "detail": f"pid-1-{comm or 'openrc-marker'}"[:128]}
    if shutil.which("systemctl") and "systemd" in comm:
        return {"init": "systemd", "detail": "pid-1-systemd"}
    if comm:
        return {"init": "unknown", "detail": f"pid-1-{comm}"[:128]}
    return {"init": "unknown", "detail": "unobserved"}


def probe_shells() -> dict[str, Any]:
    """Report which shells actually resolve on the search path."""
    present = sorted({name for name in _SHELLS if shutil.which(name)})
    return {"shells": present}


def probe_kernel_features() -> dict[str, Any]:
    """Report Linux kernel execution facilities (eBPF/BTF/tracing)."""
    system = platform.system().lower()
    if system != "linux":
        return {"has_ebpf": False, "has_btf": False, "detail": f"non-linux-{system}"}
    has_bpf_fs = Path("/sys/fs/bpf").exists()
    has_btf = Path("/sys/kernel/btf/vmlinux").is_file()
    return {
        "has_ebpf": bool(has_bpf_fs and has_btf),
        "has_btf": bool(has_btf),
        "detail": f"bpf-fs={has_bpf_fs};btf={has_btf}",
    }


def probe_cuda() -> dict[str, Any]:
    """Report NVIDIA/CUDA execution capability with compute floor."""
    out = _run(["nvidia-smi", "--query-gpu=name,driver_version,compute_cap", "--format=csv,noheader"])
    if not out.strip():
        return {"accel": "none", "cuda_major": 0, "cuda_minor": 0, "detail": "no-nvidia-gpu"}
    first = out.strip().splitlines()[0]
    parts = [item.strip() for item in first.split(",")]
    compute = parts[2] if len(parts) >= 3 else ""
    match = re.match(r"(\d+)\.(\d+)", compute)
    major, minor = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    has_ptx = shutil.which("ptxas") is not None
    return {
        "accel": "cuda",
        "cuda_major": major,
        "cuda_minor": minor,
        "has_ptx": has_ptx,
        "detail": f"{parts[0] if parts else 'gpu'};driver={parts[1] if len(parts) > 1 else '?'};cc={compute or '?'};ptxas={has_ptx}"[:256],
    }


def probe_wasm() -> dict[str, Any]:
    """Report standalone WASM runtimes on the search path."""
    present = sorted({name for name in _WASM_RUNTIMES if shutil.which(name)})
    node = shutil.which("node") is not None
    return {"has_wasm": bool(present), "wasm_runtimes": present, "has_node": node}


def probe_emulation() -> dict[str, Any]:
    """Report declared machine-emulation capability (e.g. qemu-user)."""
    provided = sorted({arch for arch in _QEMU_ARCHES if shutil.which(f"qemu-{arch}")})
    return {"emulated_arches": provided}


def collect_platform_facts() -> dict[str, Any]:
    """Collect every platform fact in one bounded pass."""
    libc = probe_libc()
    init = probe_init()
    shells = probe_shells()
    kernel = probe_kernel_features()
    cuda = probe_cuda()
    wasm = probe_wasm()
    emulation = probe_emulation()
    mem_mib = 0
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        mem_mib = int(pages * page_size // (1024 * 1024))
    except (OSError, ValueError, AttributeError):
        try:
            with open("/proc/meminfo", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MemTotal:"):
                        mem_mib = int(line.split()[1]) // 1024
                        break
        except (OSError, ValueError, UnicodeError):
            mem_mib = 0
    return {
        "libc": libc["libc"],
        "libc_detail": libc.get("detail"),
        "init": init["init"],
        "init_detail": init.get("detail"),
        "shells": shells["shells"],
        "has_ebpf": kernel["has_ebpf"],
        "has_btf": kernel["has_btf"],
        "kernel_detail": kernel.get("detail"),
        "accel": cuda["accel"],
        "cuda_major": cuda["cuda_major"],
        "cuda_minor": cuda["cuda_minor"],
        "has_ptx": cuda.get("has_ptx", False),
        "accel_detail": cuda.get("detail"),
        "has_wasm": wasm["has_wasm"],
        "wasm_runtimes": wasm["wasm_runtimes"],
        "emulated_arches": emulation["emulated_arches"],
        "mem_mib": mem_mib,
        "cpu_count": os.cpu_count() or 0,
    }


def env_from_node(node: Mapping[str, Any]) -> dict[str, Any]:
    """Build the classified WorkerEnv from a stored node record.

    No subprocesses run here: the node's ``platform`` section already
    carries the worker-observed facts. Unknown sections stay unknown, so
    a legacy node without platform facts satisfies nothing concrete.
    """
    from collections.abc import Mapping as _Mapping

    from .capability_resolution import classify_arch, classify_os, default_env

    observed = node.get("platform") if isinstance(node, _Mapping) else None
    if not isinstance(observed, _Mapping):
        observed = {}
    env = default_env()
    env.update({
        "os": classify_os(node.get("os") if isinstance(node, _Mapping) else None),
        "arch": classify_arch(node.get("architecture") if isinstance(node, _Mapping) else None),
        "libc": str(observed.get("libc", "unknown")),
        "init": str(observed.get("init", "unknown")),
        "accel": str(observed.get("accel", "unknown")),
        "cuda_major": int(observed.get("cuda_major", 0) or 0),
        "cuda_minor": int(observed.get("cuda_minor", 0) or 0),
        "has_ebpf": bool(observed.get("has_ebpf", False)),
        "has_wasm": bool(observed.get("has_wasm", False)),
        "has_ptx": bool(observed.get("has_ptx", False)),
        "mem_mib": int(observed.get("mem_mib", 0) or 0),
        "cpu_count": int(observed.get("cpu_count", 0) or 0),
        "shells": list(observed.get("shells", []) or []),
        "emulated_arches": list(observed.get("emulated_arches", []) or []),
    })
    return env


def classified_env(node: dict[str, Any], facts: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the classified WorkerEnv record schedulers consume.

    ``node`` is a ``node.collect_node_capabilities`` record; ``facts``
    defaults to a live ``collect_platform_facts`` pass. Names stay out:
    only classified facts enter the environment.
    """
    from .capability_resolution import classify_arch, classify_os, default_env

    observed = facts or collect_platform_facts()
    env = default_env()
    env.update({
        "os": classify_os(node.get("os")),
        "arch": classify_arch(node.get("architecture")),
        "libc": observed.get("libc", "unknown"),
        "init": observed.get("init", "unknown"),
        "accel": observed.get("accel", "unknown"),
        "cuda_major": int(observed.get("cuda_major", 0)),
        "cuda_minor": int(observed.get("cuda_minor", 0)),
        "has_ebpf": bool(observed.get("has_ebpf", False)),
        "has_wasm": bool(observed.get("has_wasm", False)),
        "has_ptx": bool(observed.get("has_ptx", False)),
        "mem_mib": int(observed.get("mem_mib", 0)),
        "cpu_count": int(observed.get("cpu_count", 0)),
        "shells": list(observed.get("shells", [])),
        "emulated_arches": list(observed.get("emulated_arches", [])),
    })
    return env
