"""Bounded synthetic Torch placement probe for operator-controlled evidence.

This script is deliberately outside Fabric core.  It exercises a layered
provider runtime in CPU, full-CUDA, or Accelerate sequential CPU-offload mode
and emits raw facts for later Fabric binding.  It is not a model evaluator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time


def _digest(value) -> str:
    import torch

    data = value.detach().to("cpu").contiguous().numpy().tobytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _rss() -> int | None:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except Exception:
        return None


def _parameter_bytes(model, device_type: str | None = None) -> int:
    return sum(int(parameter.numel() * parameter.element_size()) for parameter in model.parameters() if device_type is None or parameter.device.type == device_type)


def run(mode: str, *, dtype_name: str = "float32") -> dict[str, object]:
    import torch
    from torch import nn

    torch.manual_seed(20260809)
    dtype = {"float32": torch.float32, "float16": torch.float16, "bfloat16": torch.bfloat16}[dtype_name]
    device = torch.device("cuda" if mode in {"cuda", "offload"} else "cpu")
    if device.type == "cuda" and not torch.cuda.is_available():
        return {"status": "UNKNOWN", "actual_mode": mode, "reason": "CUDA_UNAVAILABLE"}

    class LayeredMLP(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.layers = nn.ModuleList([nn.Linear(2048, 2048) for _ in range(6)])

        def forward(self, value):
            for layer in self.layers:
                value = torch.tanh(layer(value))
            return value

    model = LayeredMLP().to(dtype=dtype)
    input_value = torch.randn((2, 2048), dtype=dtype)
    if mode == "cuda":
        model = model.to(device)
        input_value = input_value.to(device)
    elif mode == "offload":
        from accelerate import cpu_offload

        model = cpu_offload(model.to("cpu"), execution_device=device)
        input_value = input_value.to(device)

    if device.type == "cuda":
        torch.cuda.empty_cache()
        torch.cuda.reset_peak_memory_stats(device)
        startup_free = int(torch.cuda.mem_get_info(device)[0])
    else:
        startup_free = None
    before_rss = _rss()
    started = time.perf_counter()
    with torch.inference_mode():
        output = model(input_value)
    if device.type == "cuda":
        torch.cuda.synchronize(device)
    duration = time.perf_counter() - started
    if not bool(torch.isfinite(output).all().item()):
        return {"status": "FAIL", "actual_mode": mode, "reason": "NONFINITE_OUTPUT"}
    if device.type == "cuda":
        peak_allocated = int(torch.cuda.max_memory_allocated(device))
        peak_reserved = int(torch.cuda.max_memory_reserved(device))
    else:
        peak_allocated = peak_reserved = None
    result: dict[str, object] = {
        "status": "PASS",
        "actual_mode": "sequential-cpu-offload" if mode == "offload" else mode,
        "requested_mode": mode,
        "precision": dtype_name,
        "mechanism": "accelerate.cpu_offload" if mode == "offload" else ("torch.cuda" if mode == "cuda" else "cpu"),
        "cuda_execution": "PASS" if device.type == "cuda" else "UNKNOWN",
        "offload_hook_count": sum(1 for module in model.modules() if hasattr(module, "_hf_hook")) if mode == "offload" else 0,
        "persistent_accelerator_parameter_bytes": _parameter_bytes(model, "cuda"),
        "cpu_or_meta_parameter_bytes": _parameter_bytes(model, "cpu") + _parameter_bytes(model, "meta"),
        "peak_allocated_bytes": peak_allocated,
        "peak_reserved_bytes": peak_reserved,
        "startup_free_bytes": startup_free,
        "host_memory_bytes": _rss() or before_rss,
        "duration_seconds": round(duration, 6),
        "result_digest": _digest(output),
        "python_executable": sys.executable,
        "torch_version": torch.__version__,
        "torch_cuda_version": torch.version.cuda,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("cpu", "cuda", "offload"), required=True)
    parser.add_argument("--dtype", choices=("float32", "float16", "bfloat16"), default="float32")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.mode, dtype_name=args.dtype)
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
