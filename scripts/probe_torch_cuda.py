#!/usr/bin/env python3
"""Run a small synchronized CUDA probe in the current Python environment.

This is an optional operator workload, not a Fabric dependency.  A successful
probe requires a real CUDA operation and synchronization; discovery alone is
reported separately and never promoted to execution proof.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _finite(tensor) -> bool:
    import torch
    return bool(torch.isfinite(tensor).all().item())


def _precision_probe(torch, device: str, dtype, label: str) -> str:
    try:
        left = torch.ones((256, 256), device=device, dtype=dtype)
        right = torch.full((256, 256), 2, device=device, dtype=dtype)
        result = left @ right
        torch.cuda.synchronize()
        return "PASS" if _finite(result) else "FAIL"
    except Exception:
        return "UNKNOWN"
    finally:
        try:
            del left, right, result
        except UnboundLocalError:
            pass


def probe() -> dict[str, object]:
    captured_at = _now()
    value: dict[str, object] = {
        "schema_version": "mncs-fabric.runtime-probe-output.v0.1",
        "captured_at": captured_at,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "runtime_kind": "python",
        "accelerator_backend": "cuda",
        "accelerator": None,
        "runtime_version": None,
        "compute_capability": None,
        "supported_architectures": [],
        "execution_probe": "UNKNOWN",
        "precision_probes": {},
        "memory": {},
        "observation_source": "probe_torch_cuda.py",
        "claim_boundary": "operator-controlled synchronized runtime observation; not hardware attestation or semantic correctness",
    }
    try:
        import torch
    except Exception as exc:
        value["diagnostic"] = f"torch import failed: {type(exc).__name__}"
        return value
    value["torch_version"] = str(getattr(torch, "__version__", "unknown"))
    value["runtime_version"] = str(getattr(torch.version, "cuda", None) or "unknown")
    try:
        available = bool(torch.cuda.is_available())
    except Exception:
        available = False
    value["cuda_available"] = available
    if not available:
        value["diagnostic"] = "torch.cuda.is_available() is false"
        return value
    try:
        index = torch.cuda.current_device()
        props = torch.cuda.get_device_properties(index)
        value["accelerator"] = str(props.name)
        value["compute_capability"] = [int(props.major), int(props.minor)]
        value["supported_architectures"] = list(torch.cuda.get_arch_list())
        value["memory"] = {
            "total_bytes": int(props.total_memory),
            "free_bytes_before": int(torch.cuda.mem_get_info(index)[0]),
        }
        device = f"cuda:{index}"
        fp32 = _precision_probe(torch, device, torch.float32, "float32")
        value["precision_probes"] = {"float32": fp32}
        value["execution_probe"] = "PASS" if fp32 == "PASS" else "FAIL"
        fp16 = _precision_probe(torch, device, torch.float16, "float16")
        value["precision_probes"]["float16"] = fp16
        if hasattr(torch, "bfloat16"):
            value["precision_probes"]["bfloat16"] = _precision_probe(torch, device, torch.bfloat16, "bfloat16")
        torch.cuda.synchronize()
        value["memory"]["free_bytes_after"] = int(torch.cuda.mem_get_info(index)[0])
        value["memory"]["peak_allocated_bytes"] = int(torch.cuda.max_memory_allocated(index))
        value["memory"]["peak_reserved_bytes"] = int(torch.cuda.max_memory_reserved(index))
    except Exception as exc:
        value["execution_probe"] = "FAIL"
        value["diagnostic"] = f"synchronized CUDA probe failed: {type(exc).__name__}"
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    value = probe()
    identity_value = dict(value)
    value["probe_identity"] = "sha256:" + hashlib.sha256(json.dumps(identity_value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(encoded + "\n", encoding="utf-8")
        temporary.replace(args.output)
    print(encoded)
    return 0 if value["execution_probe"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
