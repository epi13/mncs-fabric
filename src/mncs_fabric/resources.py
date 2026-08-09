"""Provider-neutral resource observations and placement admission.

Fabric observes resources and decides whether a worker is eligible. It does
not import or operate a model runtime, and a provider-reported placement
observation remains operator-controlled evidence rather than attestation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import hashlib
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping

from .canonical import attach_identity, is_sha256_identity, sha256_identity, verify_identity
from .errors import ValidationError


RESOURCE_SCHEMA = "mncs-fabric.node-resources.v0.1"
PLACEMENT_REQUEST_SCHEMA = "mncs-fabric.execution-placement-request.v0.1"
ADMISSION_SCHEMA = "mncs-fabric.placement-admission.v0.1"
OBSERVATION_SCHEMA = "mncs-fabric.execution-placement-observation.v0.1"
REFERENCE_SCHEMA = "mncs-fabric.placement-reference.v0.1"
BINDING_SCHEMA = "mncs-fabric.placement-binding.v0.1"
MAX_RESOURCE_AGE_SECONDS = 300.0
MAX_TEXT = 256
MODES = {"cpu", "full-accelerator", "sequential-cpu-offload", "unknown"}
DISPOSITIONS = {"PASS", "UNKNOWN"}
REASONS = {
    "CPU_ELIGIBLE",
    "FULL_ACCELERATOR_ELIGIBLE",
    "SEQUENTIAL_CPU_OFFLOAD_ELIGIBLE",
    "ACCELERATOR_UNAVAILABLE",
    "ACCELERATOR_EXECUTION_UNVERIFIED",
    "PRECISION_UNAVAILABLE",
    "INSUFFICIENT_VRAM",
    "INSUFFICIENT_HOST_RAM",
    "SEQUENTIAL_OFFLOAD_RUNTIME_UNSUPPORTED",
    "RESOURCE_OBSERVATION_STALE",
    "RESOURCE_OBSERVATION_UNKNOWN",
    "CAPABILITY_UNAVAILABLE",
}
PRECISIONS = {"auto", "float32", "float16", "bfloat16"}


def _text(value: object, field: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def _nonnegative(value: object, field: str, *, allow_none: bool = True) -> int | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"{field} must be a non-negative integer or null")
    return value


def _timestamp(value: object, field: str = "captured_at") -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _probe_status(value: object, field: str) -> str:
    if value not in {"PASS", "FAIL", "UNKNOWN"}:
        raise ValidationError(f"{field} must be PASS, FAIL, or UNKNOWN")
    return str(value)


_ACCELERATOR_FIELDS = {
    "index", "vendor", "backend", "device_name", "hardware_identity",
    "total_memory_bytes", "free_memory_bytes", "driver_version",
    "runtime_version", "execution_probe", "precision_probes", "observation_source",
}


def _validate_accelerator(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ACCELERATOR_FIELDS:
        raise ValidationError("accelerator observation fields are invalid")
    if not isinstance(value["index"], int) or isinstance(value["index"], bool) or value["index"] < 0:
        raise ValidationError("accelerator index is invalid")
    for field in ("vendor", "observation_source"):
        if value[field] is not None:
            _text(value[field], field)
    for field in ("backend", "device_name", "hardware_identity", "driver_version", "runtime_version"):
        if value[field] is not None:
            _text(value[field], field)
    for field in ("total_memory_bytes", "free_memory_bytes"):
        _nonnegative(value[field], field)
    _probe_status(value["execution_probe"], "execution_probe")
    probes = value["precision_probes"]
    if not isinstance(probes, dict) or set(probes) - {"float32", "float16", "bfloat16"}:
        raise ValidationError("accelerator precision probes are invalid")
    for precision, status in probes.items():
        _probe_status(status, f"precision_probes.{precision}")
    return dict(value)


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    worker_identity: str
    captured_at: str
    host_memory_total_bytes: int | None
    host_memory_available_bytes: int | None
    cpu_logical_count: int | None
    architecture: str | None
    accelerators: tuple[dict[str, Any], ...] = ()
    observation_source: str = "unknown"
    node_fingerprint: str | None = None

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": RESOURCE_SCHEMA,
            "worker_identity": self.worker_identity,
            "captured_at": self.captured_at,
            "host_memory_total_bytes": self.host_memory_total_bytes,
            "host_memory_available_bytes": self.host_memory_available_bytes,
            "cpu_logical_count": self.cpu_logical_count,
            "architecture": self.architecture,
            "accelerators": [dict(item) for item in self.accelerators],
            "observation_source": self.observation_source,
            "node_fingerprint": self.node_fingerprint,
        }
        if include_identity:
            value["resource_snapshot_identity"] = sha256_identity(value)
        return value

    @property
    def resource_snapshot_identity(self) -> str:
        return sha256_identity(self.to_dict(include_identity=False))


def validate_resource_snapshot(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("schema_version") != RESOURCE_SCHEMA:
            raise ValidationError("unsupported resource snapshot schema")
        required = {"schema_version", "worker_identity", "captured_at", "host_memory_total_bytes", "host_memory_available_bytes", "cpu_logical_count", "architecture", "accelerators", "observation_source", "node_fingerprint", "resource_snapshot_identity"}
        if set(value) != required:
            raise ValidationError("resource snapshot fields are invalid")
        _text(value["worker_identity"], "worker_identity")
        _timestamp(value["captured_at"])
        _nonnegative(value["host_memory_total_bytes"], "host_memory_total_bytes")
        _nonnegative(value["host_memory_available_bytes"], "host_memory_available_bytes")
        if value["cpu_logical_count"] is not None and (not isinstance(value["cpu_logical_count"], int) or isinstance(value["cpu_logical_count"], bool) or value["cpu_logical_count"] < 1):
            raise ValidationError("cpu_logical_count is invalid")
        if value["architecture"] is not None:
            _text(value["architecture"], "architecture")
        if value["node_fingerprint"] is not None and not is_sha256_identity(value["node_fingerprint"]):
            raise ValidationError("node_fingerprint is invalid")
        if not isinstance(value["accelerators"], list) or len(value["accelerators"]) > 16:
            raise ValidationError("accelerators must be a bounded array")
        accelerators = [_validate_accelerator(item) for item in value["accelerators"]]
        if len({item["index"] for item in accelerators}) != len(accelerators):
            raise ValidationError("accelerator indices must be unique")
        _text(value["observation_source"], "observation_source")
        if not verify_identity(value, "resource_snapshot_identity"):
            raise ValidationError("resource snapshot identity does not verify")
        return dict(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc


def _read_linux_memory() -> tuple[int | None, int | None, str]:
    path = Path("/proc/meminfo")
    if not path.is_file():
        return None, None, "memory:unknown"
    values: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            key, _, remainder = line.partition(":")
            match = re.match(r"\s*(\d+)\s*(kB)?", remainder)
            if match:
                values[key] = int(match.group(1)) * (1024 if match.group(2) else 1)
    except (OSError, UnicodeError, ValueError):
        return None, None, "memory:unknown"
    return values.get("MemTotal"), values.get("MemAvailable"), "memory:/proc/meminfo"


def _read_windows_memory() -> tuple[int | None, int | None, str]:
    try:
        class Status(ctypes.Structure):
            _fields_ = [("length", ctypes.c_uint), ("memory_load", ctypes.c_uint), ("total", ctypes.c_ulonglong), ("available", ctypes.c_ulonglong), ("total_page", ctypes.c_ulonglong), ("available_page", ctypes.c_ulonglong), ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong), ("available_extended", ctypes.c_ulonglong)]
        status = Status()
        status.length = ctypes.sizeof(Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.total), int(status.available), "memory:GlobalMemoryStatusEx"
    except (AttributeError, OSError, TypeError):
        pass
    return None, None, "memory:unknown"


def _command(command: list[str], timeout: float = 3.0) -> str | None:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _accelerator_observations() -> tuple[list[dict[str, Any]], list[str]]:
    observations: list[dict[str, Any]] = []
    sources: list[str] = []
    smi = shutil.which("nvidia-smi")
    if smi:
        output = _command([smi, "--query-gpu=index,name,uuid,memory.total,memory.free,driver_version", "--format=csv,noheader,nounits"])
        if output is not None:
            for line in output.splitlines():
                fields = [item.strip() for item in line.split(",")]
                if len(fields) != 6:
                    continue
                try:
                    index = int(fields[0])
                    total = int(fields[3]) * 1024 * 1024
                    free = int(fields[4]) * 1024 * 1024
                except ValueError:
                    continue
                observations.append({"index": index, "vendor": "nvidia", "backend": "cuda", "device_name": fields[1] or None, "hardware_identity": fields[2] if fields[2] and fields[2] != "N/A" else None, "total_memory_bytes": total, "free_memory_bytes": free, "driver_version": fields[5] or None, "runtime_version": None, "execution_probe": "UNKNOWN", "precision_probes": {}, "observation_source": "nvidia-smi"})
            if observations:
                sources.append("nvidia-smi")
                return observations, sources
    lspci = shutil.which("lspci")
    if lspci:
        output = _command([lspci, "-nnk"])
        if output:
            for line in output.splitlines():
                lowered = line.lower()
                if "nvidia" not in lowered or not any(term in lowered for term in ("vga", "3d controller", "display")):
                    continue
                index = len(observations)
                observations.append({"index": index, "vendor": "nvidia", "backend": "cuda", "device_name": line.strip(), "hardware_identity": "sha256:" + hashlib.sha256(line.strip().encode("utf-8")).hexdigest(), "total_memory_bytes": None, "free_memory_bytes": None, "driver_version": None, "runtime_version": None, "execution_probe": "UNKNOWN", "precision_probes": {}, "observation_source": "lspci:discovery-only"})
            if observations:
                sources.append("lspci:discovery-only")
    return observations, sources


def capture_resource_snapshot(worker_identity: str, *, node_fingerprint: str | None = None) -> dict[str, Any]:
    """Capture bounded host and accelerator observations without third-party dependencies."""

    _text(worker_identity, "worker_identity")
    if platform.system().lower() == "windows":
        total, available, memory_source = _read_windows_memory()
    else:
        total, available, memory_source = _read_linux_memory()
    accelerators, accelerator_sources = _accelerator_observations()
    snapshot = ResourceSnapshot(worker_identity=worker_identity, captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), host_memory_total_bytes=total, host_memory_available_bytes=available, cpu_logical_count=os.cpu_count(), architecture=platform.machine().lower(), accelerators=tuple(accelerators), observation_source=";".join([memory_source, *accelerator_sources]), node_fingerprint=node_fingerprint)
    return snapshot.to_dict()


def resource_snapshot_age_seconds(value: Mapping[str, Any], *, now: str | None = None) -> float:
    checked = validate_resource_snapshot(dict(value))
    current = datetime.now(timezone.utc) if now is None else datetime.fromisoformat(now.replace("Z", "+00:00"))
    captured = datetime.fromisoformat(checked["captured_at"].replace("Z", "+00:00"))
    return max(0.0, (current.astimezone(timezone.utc) - captured.astimezone(timezone.utc)).total_seconds())


def resource_snapshot_is_fresh(value: Mapping[str, Any], *, max_age_seconds: float = MAX_RESOURCE_AGE_SECONDS, now: str | None = None) -> bool:
    if max_age_seconds < 0:
        raise ValidationError("resource freshness bound cannot be negative")
    return resource_snapshot_age_seconds(value, now=now) <= max_age_seconds


@dataclass(frozen=True, slots=True)
class PlacementRequest:
    execution_device: str = "auto"
    accelerator_backend: str | None = None
    offload: str = "auto"
    precision: str = "auto"
    model_storage_bytes: int = 0
    estimated_workspace_bytes: int = 0
    minimum_host_memory_bytes: int | None = None
    gpu_reserve_bytes: int = 256 * 1024 * 1024
    maximum_vram_bytes: int | None = None
    minimum_accelerator_working_bytes: int | None = None
    runtime_supports_sequential_cpu_offload: bool | None = None
    required_capabilities: tuple[str, ...] = ()
    resource_max_age_seconds: float = MAX_RESOURCE_AGE_SECONDS

    def validate(self) -> None:
        if self.execution_device not in {"auto", "cpu", "accelerator"}:
            raise ValidationError("execution_device is unsupported")
        if self.offload not in {"auto", "none", "sequential-cpu"}:
            raise ValidationError("offload is unsupported")
        if self.precision not in PRECISIONS:
            raise ValidationError("precision is unsupported")
        if self.execution_device == "cpu" and self.offload == "sequential-cpu":
            raise ValidationError("sequential CPU offload requires auto or accelerator execution")
        if self.accelerator_backend is not None:
            _text(self.accelerator_backend, "accelerator_backend", 64)
        for field in ("model_storage_bytes", "estimated_workspace_bytes", "gpu_reserve_bytes"):
            if getattr(self, field) < 0:
                raise ValidationError(f"{field} cannot be negative")
        for field in ("minimum_host_memory_bytes", "maximum_vram_bytes", "minimum_accelerator_working_bytes"):
            value = getattr(self, field)
            if value is not None and value < 1:
                raise ValidationError(f"{field} must be positive when supplied")
        if self.runtime_supports_sequential_cpu_offload not in {None, True, False}:
            raise ValidationError("runtime_supports_sequential_cpu_offload must be boolean or null")
        if len(self.required_capabilities) > 64 or len(set(self.required_capabilities)) != len(self.required_capabilities):
            raise ValidationError("required placement capabilities must be unique and bounded")
        for capability in self.required_capabilities:
            _text(capability, "required_capabilities[]", 128)
        if self.resource_max_age_seconds < 0 or self.resource_max_age_seconds > 86400:
            raise ValidationError("resource_max_age_seconds is outside its bound")

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        self.validate()
        value: dict[str, Any] = {"schema_version": PLACEMENT_REQUEST_SCHEMA, "execution_device": self.execution_device, "accelerator_backend": self.accelerator_backend, "offload": self.offload, "precision": self.precision, "model_storage_bytes": self.model_storage_bytes, "estimated_workspace_bytes": self.estimated_workspace_bytes, "minimum_host_memory_bytes": self.minimum_host_memory_bytes, "gpu_reserve_bytes": self.gpu_reserve_bytes, "maximum_vram_bytes": self.maximum_vram_bytes, "minimum_accelerator_working_bytes": self.minimum_accelerator_working_bytes, "runtime_supports_sequential_cpu_offload": self.runtime_supports_sequential_cpu_offload, "required_capabilities": list(self.required_capabilities), "resource_max_age_seconds": self.resource_max_age_seconds}
        if include_identity:
            value["placement_request_identity"] = sha256_identity(value)
        return value

    @property
    def placement_request_identity(self) -> str:
        return self.to_dict(include_identity=True)["placement_request_identity"]


def placement_request_from(value: PlacementRequest | Mapping[str, Any]) -> PlacementRequest:
    if isinstance(value, PlacementRequest):
        value.validate()
        return value
    checked = validate_placement_request(value)
    return PlacementRequest(execution_device=checked["execution_device"], accelerator_backend=checked["accelerator_backend"], offload=checked["offload"], precision=checked["precision"], model_storage_bytes=checked["model_storage_bytes"], estimated_workspace_bytes=checked["estimated_workspace_bytes"], minimum_host_memory_bytes=checked["minimum_host_memory_bytes"], gpu_reserve_bytes=checked["gpu_reserve_bytes"], maximum_vram_bytes=checked["maximum_vram_bytes"], minimum_accelerator_working_bytes=checked["minimum_accelerator_working_bytes"], runtime_supports_sequential_cpu_offload=checked["runtime_supports_sequential_cpu_offload"], required_capabilities=tuple(checked["required_capabilities"]), resource_max_age_seconds=checked["resource_max_age_seconds"])


def validate_placement_request(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("schema_version") != PLACEMENT_REQUEST_SCHEMA:
            raise ValidationError("unsupported placement request schema")
        required = {"schema_version", "execution_device", "accelerator_backend", "offload", "precision", "model_storage_bytes", "estimated_workspace_bytes", "minimum_host_memory_bytes", "gpu_reserve_bytes", "maximum_vram_bytes", "minimum_accelerator_working_bytes", "runtime_supports_sequential_cpu_offload", "required_capabilities", "resource_max_age_seconds", "placement_request_identity"}
        if set(value) != required:
            raise ValidationError("placement request fields are invalid")
        request = PlacementRequest(execution_device=value["execution_device"], accelerator_backend=value["accelerator_backend"], offload=value["offload"], precision=value["precision"], model_storage_bytes=value["model_storage_bytes"], estimated_workspace_bytes=value["estimated_workspace_bytes"], minimum_host_memory_bytes=value["minimum_host_memory_bytes"], gpu_reserve_bytes=value["gpu_reserve_bytes"], maximum_vram_bytes=value["maximum_vram_bytes"], minimum_accelerator_working_bytes=value["minimum_accelerator_working_bytes"], runtime_supports_sequential_cpu_offload=value["runtime_supports_sequential_cpu_offload"], required_capabilities=tuple(value["required_capabilities"]), resource_max_age_seconds=value["resource_max_age_seconds"])
        request.validate()
        if not verify_identity(value, "placement_request_identity"):
            raise ValidationError("placement request identity does not verify")
        return dict(value)
    except (ValidationError, TypeError, ValueError) as exc:
        raise error_type(str(exc)) from exc


def _precision_bytes(model_bytes: int, precision: str) -> int:
    return (model_bytes + 1) // 2 if precision in {"float16", "bfloat16"} else model_bytes


def _host_requirement(request: PlacementRequest, mode: str) -> int:
    minimum = request.minimum_host_memory_bytes or 0
    if mode == "sequential-cpu-offload":
        return max(minimum, request.model_storage_bytes)
    return minimum


def _accelerator(snapshot: Mapping[str, Any], request: PlacementRequest) -> dict[str, Any] | None:
    candidates = sorted(snapshot["accelerators"], key=lambda item: item["index"])
    if request.accelerator_backend is not None:
        candidates = [item for item in candidates if item.get("backend") == request.accelerator_backend]
    return candidates[0] if candidates else None


def _precision_status(accelerator: Mapping[str, Any], precision: str) -> str:
    if precision == "auto":
        for candidate in ("float32", "float16", "bfloat16"):
            if accelerator.get("precision_probes", {}).get(candidate) == "PASS":
                return candidate
        return "unknown"
    return precision if accelerator.get("precision_probes", {}).get(precision) == "PASS" else "unknown"


def _decision(*, snapshot: Mapping[str, Any], request: PlacementRequest, disposition: str, mode: str, reason_code: str, reason: str, precision: str = "unknown", accelerator: Mapping[str, Any] | None = None, effective_gpu_budget: int | None = None, required_gpu: int = 0, required_host: int = 0) -> dict[str, Any]:
    value = {"schema_version": ADMISSION_SCHEMA, "worker_identity": snapshot["worker_identity"], "placement_request_identity": request.placement_request_identity, "resource_snapshot_identity": snapshot["resource_snapshot_identity"], "disposition": disposition, "admission_mode": mode, "precision": precision, "reason_code": reason_code, "reason": reason, "selected_accelerator_identity": accelerator.get("hardware_identity") if accelerator else None, "effective_accelerator_budget_bytes": effective_gpu_budget, "required_accelerator_bytes": required_gpu, "required_host_memory_bytes": required_host, "claim_boundary": "resource admission observation; not runtime execution proof, attestation, correctness, or assurance"}
    return attach_identity(value, "decision_identity")


def evaluate_placement(request_value: PlacementRequest | Mapping[str, Any], snapshot_value: Mapping[str, Any], worker_capabilities: frozenset[str] = frozenset()) -> dict[str, Any]:
    request = placement_request_from(request_value)
    snapshot = validate_resource_snapshot(snapshot_value)
    required_capabilities = set(request.required_capabilities)
    missing = sorted(required_capabilities - set(worker_capabilities))
    if missing:
        return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="CAPABILITY_UNAVAILABLE", reason=str(missing))
    if not resource_snapshot_is_fresh(snapshot, max_age_seconds=request.resource_max_age_seconds):
        return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="RESOURCE_OBSERVATION_STALE", reason="resource snapshot exceeds freshness bound")
    host_available = snapshot.get("host_memory_available_bytes")
    accelerator = _accelerator(snapshot, request)
    host_unknown = host_available is None

    def cpu_decision() -> dict[str, Any]:
        precision = "float32" if request.precision == "auto" else request.precision
        if precision != "float32" and f"placement:cpu-precision:{precision}" not in worker_capabilities:
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="PRECISION_UNAVAILABLE", reason="CPU precision is not observed", precision=precision)
        required_host = _host_requirement(request, "cpu")
        if required_host and host_unknown:
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="RESOURCE_OBSERVATION_UNKNOWN", reason="host memory is unknown", precision=precision, required_host=required_host)
        if required_host and int(host_available or 0) < required_host:
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="INSUFFICIENT_HOST_RAM", reason="available host memory is below the request", precision=precision, required_host=required_host)
        return _decision(snapshot=snapshot, request=request, disposition="PASS", mode="cpu", reason_code="CPU_ELIGIBLE", reason="CPU resource requirements are satisfied", precision=precision, required_host=required_host)

    if request.execution_device == "cpu":
        return cpu_decision()
    if accelerator is None:
        if request.execution_device == "accelerator" or request.offload == "sequential-cpu":
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="ACCELERATOR_UNAVAILABLE", reason="requested accelerator backend is not observed")
        return cpu_decision()
    if accelerator.get("execution_probe") != "PASS":
        if request.execution_device == "accelerator" or request.offload == "sequential-cpu":
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="ACCELERATOR_EXECUTION_UNVERIFIED", reason="accelerator was discovered but executable probe did not pass", accelerator=accelerator)
        return cpu_decision()
    precision = _precision_status(accelerator, request.precision)
    if precision == "unknown":
        return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="PRECISION_UNAVAILABLE", reason="requested accelerator precision was not probed", accelerator=accelerator)
    free = accelerator.get("free_memory_bytes")
    if free is None:
        return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="RESOURCE_OBSERVATION_UNKNOWN", reason="accelerator free memory is unknown", precision=precision, accelerator=accelerator)
    effective = min(free, request.maximum_vram_bytes) if request.maximum_vram_bytes is not None else free
    effective = max(0, effective - request.gpu_reserve_bytes)
    required = _precision_bytes(request.model_storage_bytes, precision) + request.estimated_workspace_bytes
    full_fits = required <= effective
    if request.offload == "none" or (request.offload == "auto" and full_fits):
        if full_fits:
            return _decision(snapshot=snapshot, request=request, disposition="PASS", mode="full-accelerator", reason_code="FULL_ACCELERATOR_ELIGIBLE", reason="full accelerator fits the effective observed budget", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=required, required_host=_host_requirement(request, "full-accelerator"))
        if request.execution_device == "accelerator":
            return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="INSUFFICIENT_VRAM", reason="full accelerator exceeds the effective observed budget", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=required)
    if request.offload == "sequential-cpu" or (request.offload == "auto" and not full_fits):
        if request.runtime_supports_sequential_cpu_offload is not True:
            if request.offload == "sequential-cpu" or request.execution_device == "accelerator":
                return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="SEQUENTIAL_OFFLOAD_RUNTIME_UNSUPPORTED", reason="consumer runtime did not declare sequential offload support", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=required)
        else:
            working = request.minimum_accelerator_working_bytes or request.estimated_workspace_bytes
            required_host = _host_requirement(request, "sequential-cpu-offload")
            if host_unknown and required_host:
                return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="RESOURCE_OBSERVATION_UNKNOWN", reason="host memory is unknown for sequential offload", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=working, required_host=required_host)
            if required_host and int(host_available or 0) < required_host:
                return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="INSUFFICIENT_HOST_RAM", reason="host memory is insufficient for sequential offload", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=working, required_host=required_host)
            if working > effective:
                return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="INSUFFICIENT_VRAM", reason="minimum accelerator working memory exceeds the effective budget", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=working, required_host=required_host)
            return _decision(snapshot=snapshot, request=request, disposition="PASS", mode="sequential-cpu-offload", reason_code="SEQUENTIAL_CPU_OFFLOAD_ELIGIBLE", reason="sequential offload resources are sufficient", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=working, required_host=required_host)
    if request.execution_device == "auto":
        return cpu_decision()
    return _decision(snapshot=snapshot, request=request, disposition="UNKNOWN", mode="unknown", reason_code="INSUFFICIENT_VRAM", reason="requested accelerator placement is unavailable", precision=precision, accelerator=accelerator, effective_gpu_budget=effective, required_gpu=required)


def validate_admission(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("schema_version") != ADMISSION_SCHEMA:
            raise ValidationError("unsupported placement admission schema")
        if not isinstance(value.get("decision_identity"), str) or not verify_identity(value, "decision_identity"):
            raise ValidationError("placement admission identity does not verify")
        if value.get("disposition") not in DISPOSITIONS or value.get("admission_mode") not in MODES or value.get("reason_code") not in REASONS:
            raise ValidationError("placement admission disposition or reason is invalid")
        if not is_sha256_identity(value.get("placement_request_identity")) or not is_sha256_identity(value.get("resource_snapshot_identity")):
            raise ValidationError("placement admission identities are invalid")
        return dict(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc


def build_placement_reference(admission: Mapping[str, Any], observation_identity: str | None = None) -> dict[str, Any]:
    checked = validate_admission(dict(admission))
    value = {"schema_version": REFERENCE_SCHEMA, "placement_request_identity": checked["placement_request_identity"], "resource_snapshot_identity": checked["resource_snapshot_identity"], "admission_decision_identity": checked["decision_identity"], "admission_mode": checked["admission_mode"], "placement_observation_identity": observation_identity}
    if observation_identity is not None and not is_sha256_identity(observation_identity):
        raise ValidationError("placement observation identity is invalid")
    return attach_identity(value, "reference_identity")


def validate_placement_reference(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("schema_version") != REFERENCE_SCHEMA:
            raise ValidationError("unsupported placement reference schema")
        required = {"schema_version", "placement_request_identity", "resource_snapshot_identity", "admission_decision_identity", "admission_mode", "placement_observation_identity", "reference_identity"}
        if set(value) != required or value.get("admission_mode") not in MODES:
            raise ValidationError("placement reference fields are invalid")
        for field in ("placement_request_identity", "resource_snapshot_identity", "admission_decision_identity"):
            if not is_sha256_identity(value.get(field)):
                raise ValidationError(f"{field} is invalid")
        if value["placement_observation_identity"] is not None and not is_sha256_identity(value["placement_observation_identity"]):
            raise ValidationError("placement observation identity is invalid")
        if not verify_identity(value, "reference_identity"):
            raise ValidationError("placement reference identity does not verify")
        return dict(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc


def build_placement_binding(*, result: Mapping[str, Any], observation: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a consumer-visible runtime placement observation to one result."""

    checked_observation = validate_placement_observation(dict(observation))
    record = result.get("record")
    receipt = result.get("receipt")
    admission = result.get("placement_admission")
    if not isinstance(record, Mapping) or not isinstance(receipt, Mapping) or not isinstance(admission, Mapping):
        raise ValidationError("placement binding requires a record, receipt, and admission")
    checked_admission = validate_admission(dict(admission))
    if checked_observation["worker_identity"] != result.get("worker_identity") or checked_observation["worker_identity"] != record.get("worker_identity"):
        raise ValidationError("placement observation worker does not match result")
    if checked_observation["placement_request_identity"] != checked_admission["placement_request_identity"]:
        raise ValidationError("placement observation request does not match admission")
    if checked_observation["resource_snapshot_identity"] != checked_admission["resource_snapshot_identity"] or checked_observation["admission_decision_identity"] != checked_admission["decision_identity"]:
        raise ValidationError("placement observation does not match admission")
    value = {
        "schema_version": BINDING_SCHEMA,
        "worker_identity": result.get("worker_identity"),
        "request_identity": result.get("request_identity"),
        "record_identity": record.get("record_id"),
        "receipt_identity": receipt.get("receipt_identity"),
        "placement_request_identity": checked_observation["placement_request_identity"],
        "resource_snapshot_identity": checked_observation["resource_snapshot_identity"],
        "admission_decision_identity": checked_observation["admission_decision_identity"],
        "observation_identity": checked_observation["observation_identity"],
        "claim_boundary": "placement provenance linkage only; runtime observations are not hardware attestation, correctness, assurance, custody, independence, or conformance",
    }
    for field in ("worker_identity", "request_identity", "record_identity", "receipt_identity"):
        if not isinstance(value[field], str) or not value[field]:
            raise ValidationError(f"placement binding {field} is missing")
    for field in ("request_identity", "record_identity", "receipt_identity"):
        if not is_sha256_identity(value[field]):
            raise ValidationError(f"placement binding {field} is invalid")
    return attach_identity(value, "binding_identity")


def validate_placement_binding(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or value.get("schema_version") != BINDING_SCHEMA:
            raise ValidationError("unsupported placement binding schema")
        required = {"schema_version", "worker_identity", "request_identity", "record_identity", "receipt_identity", "placement_request_identity", "resource_snapshot_identity", "admission_decision_identity", "observation_identity", "claim_boundary", "binding_identity"}
        if set(value) != required:
            raise ValidationError("placement binding fields are invalid")
        for field in ("worker_identity", "claim_boundary"):
            _text(value[field], field, 512)
        for field in ("request_identity", "record_identity", "receipt_identity", "placement_request_identity", "resource_snapshot_identity", "admission_decision_identity", "observation_identity"):
            if not is_sha256_identity(value[field]):
                raise ValidationError(f"placement binding {field} is invalid")
        if not verify_identity(value, "binding_identity"):
            raise ValidationError("placement binding identity does not verify")
        return dict(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc


_OBSERVATION_FIELDS = {"schema_version", "worker_identity", "placement_request_identity", "resource_snapshot_identity", "admission_decision_identity", "planned_mode", "actual_mode", "accelerator_backend", "accelerator_identity", "precision", "model_storage_bytes", "workspace_bytes", "startup_free_accelerator_bytes", "peak_accelerator_allocated_bytes", "peak_accelerator_reserved_bytes", "persistent_accelerator_parameter_bytes", "cpu_or_meta_parameter_bytes", "offload_hook_count", "fallback_occurred", "oom_occurred", "runtime_probe_identity", "observation_source", "claim_boundary"}


def build_placement_observation(*, worker_identity: str, placement_request_identity: str, resource_snapshot_identity: str, admission_decision_identity: str, planned_mode: str, actual_mode: str, accelerator_backend: str | None = None, accelerator_identity: str | None = None, precision: str = "auto", model_storage_bytes: int | None = None, workspace_bytes: int | None = None, startup_free_accelerator_bytes: int | None = None, peak_accelerator_allocated_bytes: int | None = None, peak_accelerator_reserved_bytes: int | None = None, persistent_accelerator_parameter_bytes: int | None = None, cpu_or_meta_parameter_bytes: int | None = None, offload_hook_count: int | None = None, fallback_occurred: bool = False, oom_occurred: bool = False, runtime_probe_identity: str | None = None, observation_source: str = "consumer-runtime", claim_boundary: str = "operator-controlled runtime placement observation; not hardware attestation, correctness, assurance, custody, independence, or conformance") -> dict[str, Any]:
    value: dict[str, Any] = {"schema_version": OBSERVATION_SCHEMA, "worker_identity": worker_identity, "placement_request_identity": placement_request_identity, "resource_snapshot_identity": resource_snapshot_identity, "admission_decision_identity": admission_decision_identity, "planned_mode": planned_mode, "actual_mode": actual_mode, "accelerator_backend": accelerator_backend, "accelerator_identity": accelerator_identity, "precision": precision, "model_storage_bytes": model_storage_bytes, "workspace_bytes": workspace_bytes, "startup_free_accelerator_bytes": startup_free_accelerator_bytes, "peak_accelerator_allocated_bytes": peak_accelerator_allocated_bytes, "peak_accelerator_reserved_bytes": peak_accelerator_reserved_bytes, "persistent_accelerator_parameter_bytes": persistent_accelerator_parameter_bytes, "cpu_or_meta_parameter_bytes": cpu_or_meta_parameter_bytes, "offload_hook_count": offload_hook_count, "fallback_occurred": fallback_occurred, "oom_occurred": oom_occurred, "runtime_probe_identity": runtime_probe_identity, "observation_source": observation_source, "claim_boundary": claim_boundary}
    return attach_identity(value, "observation_identity")


def validate_placement_observation(value: object, *, error_type: type[Exception] = ValidationError) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or set(value) != (_OBSERVATION_FIELDS | {"observation_identity"}) or value.get("schema_version") != OBSERVATION_SCHEMA:
            raise ValidationError("placement observation fields are invalid")
        for field in ("worker_identity", "observation_source", "claim_boundary"):
            _text(value.get(field), field, 512)
        for field in ("placement_request_identity", "resource_snapshot_identity", "admission_decision_identity"):
            if not is_sha256_identity(value.get(field)):
                raise ValidationError(f"{field} is invalid")
        if value.get("planned_mode") not in MODES or value.get("actual_mode") not in MODES or value.get("precision") not in PRECISIONS:
            raise ValidationError("placement observation mode or precision is invalid")
        for field in ("model_storage_bytes", "workspace_bytes", "startup_free_accelerator_bytes", "peak_accelerator_allocated_bytes", "peak_accelerator_reserved_bytes", "persistent_accelerator_parameter_bytes", "cpu_or_meta_parameter_bytes", "offload_hook_count"):
            _nonnegative(value.get(field), field)
        if not isinstance(value["fallback_occurred"], bool) or not isinstance(value["oom_occurred"], bool):
            raise ValidationError("placement observation boolean fields are invalid")
        if value["runtime_probe_identity"] is not None and not is_sha256_identity(value["runtime_probe_identity"]):
            raise ValidationError("runtime_probe_identity is invalid")
        if not verify_identity(value, "observation_identity"):
            raise ValidationError("placement observation identity does not verify")
        return dict(value)
    except ValidationError as exc:
        raise error_type(str(exc)) from exc
