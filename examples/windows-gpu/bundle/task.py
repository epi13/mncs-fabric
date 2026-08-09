"""Small operator-controlled CUDA execution fixture.

Fabric transports this file as an immutable bundle; Torch remains an optional
consumer/runtime dependency on the worker and is not a Fabric dependency.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import torch


torch.manual_seed(0)
left = torch.arange(256, dtype=torch.float32, device="cuda").reshape(16, 16)
right = torch.eye(16, dtype=torch.float32, device="cuda")
result = left @ right
torch.cuda.synchronize()
raw = result.detach().cpu().numpy().tobytes()
Path("gpu-result.json").write_text(json.dumps({
    "backend": "cuda",
    "dtype": "float32",
    "result_identity": "sha256:" + hashlib.sha256(raw).hexdigest(),
    "finite": bool(torch.isfinite(result).all().item()),
}, sort_keys=True), encoding="utf-8")
