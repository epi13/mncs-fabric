"""Bounded execution-runtime profiles and operator-controlled observations.

Fabric owns the identity and validation boundary for the interpreter that
launches a worker.  It does not install packages or implement a provider
runtime.  A runtime observation is deliberately a companion record: a probe
can run before the eventual Fabric receipt exists and is bound afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
import platform
import sys

from .artifacts import file_identity
from .canonical import attach_identity, is_sha256_identity, sha256_identity, verify_identity
from .errors import ValidationError


RUNTIME_PROFILE_SCHEMA = "mncs-fabric.runtime-profile.v0.1"
RUNTIME_OBSERVATION_SCHEMA = "mncs-fabric.runtime-observation.v0.1"
RUNTIME_BINDING_SCHEMA = "mncs-fabric.runtime-binding.v0.1"
MAX_RUNTIME_AGE_SECONDS = 3600.0
_STATUSES = {"PASS", "FAIL", "UNKNOWN"}


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
        raise ValidationError(f"{field} must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _status(value: object, field: str) -> str:
    if value not in _STATUSES:
        raise ValidationError(f"{field} must be PASS, FAIL, or UNKNOWN")
    return str(value)


def _receipt_identity(value: object) -> bool:
    """MNCS receipts use a bare hexadecimal digest for historical reasons."""

    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    worker_identity: str
    runtime_kind: str
    logical_name: str
    python_version: str
    executable_identity: str | None
    captured_at: str
    observation_source: str = "worker-observed"

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": RUNTIME_PROFILE_SCHEMA,
            "worker_identity": self.worker_identity,
            "runtime_kind": self.runtime_kind,
            "logical_name": self.logical_name,
            "python_version": self.python_version,
            "executable_identity": self.executable_identity,
            "captured_at": self.captured_at,
            "observation_source": self.observation_source,
            "claim_boundary": "operator-provisioned runtime description; not package provenance, attestation, or semantic correctness",
        }
        if include_identity:
            value["runtime_profile_identity"] = sha256_identity(value)
        return value

    @property
    def runtime_profile_identity(self) -> str:
        return self.to_dict()["runtime_profile_identity"]


def build_runtime_profile(
    worker_identity: str,
    *,
    executable: Path | None = None,
    logical_name: str = "worker-python",
    python_version: str | None = None,
    captured_at: str | None = None,
    observation_source: str = "worker-observed",
) -> dict[str, Any]:
    """Describe the interpreter that owns the worker process.

    The executable path is intentionally not serialized.  Its content
    identity is portable; its path is operator-local configuration.
    """

    _text(worker_identity, "worker_identity")
    executable = Path(executable or sys.executable).resolve()
    try:
        _, executable_identity = file_identity(executable)
    except OSError:
        executable_identity = None
    profile = RuntimeProfile(
        worker_identity=worker_identity,
        runtime_kind="python",
        logical_name=_text(logical_name, "logical_name", 128),
        python_version=_text(python_version or platform.python_version(), "python_version", 64),
        executable_identity=executable_identity,
        captured_at=_timestamp(captured_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
        observation_source=_text(observation_source, "observation_source"),
    )
    return profile.to_dict()


def validate_runtime_profile(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != RUNTIME_PROFILE_SCHEMA:
        raise ValidationError("unsupported runtime profile schema")
    required = {
        "schema_version", "worker_identity", "runtime_kind", "logical_name",
        "python_version", "executable_identity", "captured_at", "observation_source",
        "claim_boundary", "runtime_profile_identity",
    }
    if set(value) != required or not verify_identity(value, "runtime_profile_identity"):
        raise ValidationError("runtime profile fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("runtime profile is bound to another worker")
    if value["runtime_kind"] != "python":
        raise ValidationError("unsupported runtime profile kind")
    _text(value["logical_name"], "logical_name", 128)
    _text(value["python_version"], "python_version", 64)
    if value["executable_identity"] is not None and not is_sha256_identity(value["executable_identity"]):
        raise ValidationError("runtime executable identity is invalid")
    _timestamp(value["captured_at"])
    _text(value["observation_source"], "observation_source")
    _text(value["claim_boundary"], "claim_boundary", 512)
    return dict(value)


def build_runtime_observation(
    *,
    worker_identity: str,
    runtime_profile: Mapping[str, Any],
    probe: Mapping[str, Any],
    captured_at: str | None = None,
    observation_source: str = "runtime-probe",
) -> dict[str, Any]:
    """Normalize bounded output from an optional provider/runtime probe."""

    profile = validate_runtime_profile(runtime_profile, expected_worker_id=worker_identity)
    if not isinstance(probe, Mapping):
        raise ValidationError("runtime probe output must be an object")
    execution_probe = _status(probe.get("execution_probe", "UNKNOWN"), "execution_probe")
    precision_input = probe.get("precision_probes", {})
    if not isinstance(precision_input, Mapping) or set(precision_input) - {"float32", "float16", "bfloat16"}:
        raise ValidationError("runtime precision probes are invalid")
    precision_probes = {str(key): _status(status, f"precision_probes.{key}") for key, status in precision_input.items()}
    accelerator = probe.get("accelerator")
    if accelerator is not None:
        _text(accelerator, "accelerator", 256)
    backend = probe.get("accelerator_backend")
    if backend is not None:
        _text(backend, "accelerator_backend", 64)
    values: dict[str, Any] = {
        "schema_version": RUNTIME_OBSERVATION_SCHEMA,
        "worker_identity": worker_identity,
        "runtime_profile_identity": profile["runtime_profile_identity"],
        "runtime_kind": profile["runtime_kind"],
        "python_version": _text(probe.get("python_version", profile["python_version"]), "python_version", 64),
        "python_executable_identity": probe.get("python_executable_identity", profile["executable_identity"]),
        "accelerator_backend": backend,
        "accelerator": accelerator,
        "driver_identity": _optional_text(probe.get("driver_identity"), "driver_identity", 256),
        "runtime_version": _optional_text(probe.get("runtime_version"), "runtime_version", 128),
        "runtime_execution_probe": execution_probe,
        "precision_probes": precision_probes,
        "probe_identity": _optional_text(probe.get("probe_identity"), "probe_identity", 256),
        "captured_at": _timestamp(captured_at or probe.get("captured_at") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
        "observation_source": _text(observation_source, "observation_source"),
        "claim_boundary": "operator-controlled runtime observation; not hardware attestation, worker honesty, or semantic correctness",
    }
    if values["python_executable_identity"] is not None and not is_sha256_identity(values["python_executable_identity"]):
        raise ValidationError("runtime Python executable identity is invalid")
    return attach_identity(values, "runtime_observation_identity")


def validate_runtime_observation(value: object, *, expected_worker_id: str | None = None, expected_profile_identity: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != RUNTIME_OBSERVATION_SCHEMA:
        raise ValidationError("unsupported runtime observation schema")
    required = {
        "schema_version", "worker_identity", "runtime_profile_identity", "runtime_kind",
        "python_version", "python_executable_identity", "accelerator_backend", "accelerator",
        "driver_identity", "runtime_version", "runtime_execution_probe", "precision_probes",
        "probe_identity", "captured_at", "observation_source", "claim_boundary",
        "runtime_observation_identity",
    }
    if set(value) != required or not verify_identity(value, "runtime_observation_identity"):
        raise ValidationError("runtime observation fields or identity are invalid")
    worker_id = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker_id != expected_worker_id:
        raise ValidationError("runtime observation is bound to another worker")
    if expected_profile_identity is not None and value["runtime_profile_identity"] != expected_profile_identity:
        raise ValidationError("runtime observation profile identity does not match")
    if not is_sha256_identity(value["runtime_profile_identity"]):
        raise ValidationError("runtime profile identity is invalid")
    if value["runtime_kind"] != "python":
        raise ValidationError("runtime observation kind is unsupported")
    _text(value["python_version"], "python_version", 64)
    if value["python_executable_identity"] is not None and not is_sha256_identity(value["python_executable_identity"]):
        raise ValidationError("runtime executable identity is invalid")
    _optional_text(value["accelerator_backend"], "accelerator_backend", 64)
    _optional_text(value["accelerator"], "accelerator", 256)
    _optional_text(value["driver_identity"], "driver_identity", 256)
    _optional_text(value["runtime_version"], "runtime_version", 128)
    _status(value["runtime_execution_probe"], "runtime_execution_probe")
    if not isinstance(value["precision_probes"], dict) or set(value["precision_probes"]) - {"float32", "float16", "bfloat16"}:
        raise ValidationError("runtime precision probes are invalid")
    for key, status in value["precision_probes"].items():
        _status(status, f"precision_probes.{key}")
    _optional_text(value["probe_identity"], "probe_identity", 256)
    _timestamp(value["captured_at"])
    _text(value["observation_source"], "observation_source")
    _text(value["claim_boundary"], "claim_boundary", 512)
    return dict(value)


def runtime_observation_is_fresh(value: Mapping[str, Any], *, max_age_seconds: float = MAX_RUNTIME_AGE_SECONDS, now: str | None = None) -> bool:
    checked = validate_runtime_observation(dict(value))
    if max_age_seconds < 0:
        raise ValidationError("runtime observation freshness bound cannot be negative")
    current = datetime.now(timezone.utc) if now is None else datetime.fromisoformat(now.replace("Z", "+00:00"))
    captured = datetime.fromisoformat(checked["captured_at"].replace("Z", "+00:00"))
    return (current.astimezone(timezone.utc) - captured.astimezone(timezone.utc)).total_seconds() <= max_age_seconds


def build_runtime_binding(*, observation: Mapping[str, Any], worker_identity: str, request_identity: str | None, record_identity: str | None, receipt_identity: str | None) -> dict[str, Any]:
    checked = validate_runtime_observation(observation, expected_worker_id=worker_identity)
    value = {
        "schema_version": RUNTIME_BINDING_SCHEMA,
        "worker_identity": worker_identity,
        "runtime_profile_identity": checked["runtime_profile_identity"],
        "runtime_observation_identity": checked["runtime_observation_identity"],
        "request_identity": request_identity,
        "record_identity": record_identity,
        "receipt_identity": receipt_identity,
        "claim_boundary": "identity linkage only; runtime observations remain operator-controlled evidence",
    }
    return attach_identity(value, "runtime_binding_identity")


def validate_runtime_binding(value: object, *, expected_worker_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != RUNTIME_BINDING_SCHEMA:
        raise ValidationError("unsupported runtime binding schema")
    required = {"schema_version", "worker_identity", "runtime_profile_identity", "runtime_observation_identity", "request_identity", "record_identity", "receipt_identity", "claim_boundary", "runtime_binding_identity"}
    if set(value) != required or not verify_identity(value, "runtime_binding_identity"):
        raise ValidationError("runtime binding fields or identity are invalid")
    worker = _text(value["worker_identity"], "worker_identity")
    if expected_worker_id is not None and worker != expected_worker_id:
        raise ValidationError("runtime binding is bound to another worker")
    for field in ("runtime_profile_identity", "runtime_observation_identity"):
        if not is_sha256_identity(value[field]):
            raise ValidationError(f"{field} is invalid")
    _optional_text(value["request_identity"], "request_identity", 256)
    for field in ("record_identity", "receipt_identity"):
        if value[field] is not None and not (is_sha256_identity(value[field]) or (field == "receipt_identity" and _receipt_identity(value[field]))):
            raise ValidationError(f"{field} is invalid")
    _text(value["claim_boundary"], "claim_boundary", 512)
    return dict(value)
