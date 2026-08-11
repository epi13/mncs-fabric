"""Versioned operator-owned registry for known remote Fabric workers.

Registry membership records how a controller may attempt an authenticated
connection.  It is not discovery, liveness, enrollment, or authorization.
Private-key bytes are never embedded; entries contain filesystem references
that are revalidated before a transport can be constructed.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_json_bytes
from .enrollment import TrustStore
from .errors import ProtocolError, StorageError, ValidationError
from .store import _exclusive_lock

WORKER_REGISTRY_SCHEMA = "mncs-fabric.worker-registry.v0.1"
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_REGISTRY_WORKERS = 256
MAX_LABELS = 32
_LABEL = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def _text(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{field} must be bounded non-empty text")
    if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value):
        raise ValidationError(f"{field} must not contain control characters")
    return value


def _path_reference(value: object, field: str) -> str:
    reference = _text(value, field)
    expanded = Path(reference).expanduser()
    if not expanded.is_absolute():
        raise ValidationError(f"{field} must be an absolute or home-relative path")
    return reference


@dataclass(frozen=True, slots=True)
class RegistryWorker:
    """One known remote endpoint and its controller-side trust references."""

    worker_id: str
    host: str
    port: int
    capabilities: tuple[str, ...]
    ca_file: str
    client_certificate: str
    client_key: str
    trust_state: str
    concurrency_limit: int = 1
    timeout: float = 5.0
    connect_timeout: float | None = None
    control_timeout: float | None = None
    execution_timeout_overhead: float = 5.0
    labels: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _text(self.worker_id, "worker_id", 256)
        host = _text(self.host, "host", 512)
        if any(value in host for value in ("/", "@", "://")) or host != host.strip():
            raise ValidationError("host must be an explicit hostname or address without credentials")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValidationError("port must be between 1 and 65535")
        if (
            not self.capabilities
            or len(self.capabilities) > 64
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ValidationError("capabilities must be bounded, unique, and non-empty")
        for capability in self.capabilities:
            _text(capability, "capability", 128)
        for field in ("ca_file", "client_certificate", "client_key", "trust_state"):
            _path_reference(getattr(self, field), field)
        if (
            not isinstance(self.concurrency_limit, int)
            or isinstance(self.concurrency_limit, bool)
            or not 1 <= self.concurrency_limit <= 64
            or not 0 < self.timeout <= 300
            or (self.connect_timeout is not None and not 0 < self.connect_timeout <= 300)
            or (self.control_timeout is not None and not 0 < self.control_timeout <= 300)
            or not 0 < self.execution_timeout_overhead <= 300
        ):
            raise ValidationError("worker registry bounds are invalid")
        if len(self.labels) > MAX_LABELS or len({key for key, _ in self.labels}) != len(self.labels):
            raise ValidationError("worker labels must be bounded and unique")
        for key, value in self.labels:
            if not _LABEL.fullmatch(key):
                raise ValidationError("worker label keys must use bounded identifier syntax")
            _text(value, f"labels.{key}", 256)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RegistryWorker":
        allowed = {
            "worker_id", "host", "port", "capabilities", "ca_file",
            "client_certificate", "client_key", "trust_state", "concurrency_limit",
            "timeout", "connect_timeout", "control_timeout",
            "execution_timeout_overhead", "labels",
        }
        if set(value) != allowed:
            raise ValidationError("registry worker has an unexpected field set")
        capabilities = value.get("capabilities")
        labels = value.get("labels")
        if not isinstance(capabilities, list) or not isinstance(labels, dict):
            raise ValidationError("registry worker capabilities/labels have invalid shapes")
        try:
            return cls(
                worker_id=value.get("worker_id"),
                host=value.get("host"),
                port=value.get("port"),
                capabilities=tuple(capabilities),
                ca_file=value.get("ca_file"),
                client_certificate=value.get("client_certificate"),
                client_key=value.get("client_key"),
                trust_state=value.get("trust_state"),
                concurrency_limit=value.get("concurrency_limit"),
                timeout=float(value.get("timeout")),
                connect_timeout=(
                    float(value["connect_timeout"])
                    if value.get("connect_timeout") is not None
                    else None
                ),
                control_timeout=(
                    float(value["control_timeout"])
                    if value.get("control_timeout") is not None
                    else None
                ),
                execution_timeout_overhead=float(
                    value.get("execution_timeout_overhead")
                ),
                labels=tuple(sorted((str(key), item) for key, item in labels.items())),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError("registry worker contains invalid numeric fields") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "host": self.host,
            "port": self.port,
            "capabilities": list(self.capabilities),
            "ca_file": self.ca_file,
            "client_certificate": self.client_certificate,
            "client_key": self.client_key,
            "trust_state": self.trust_state,
            "concurrency_limit": self.concurrency_limit,
            "timeout": self.timeout,
            "connect_timeout": self.connect_timeout,
            "control_timeout": self.control_timeout,
            "execution_timeout_overhead": self.execution_timeout_overhead,
            "labels": dict(self.labels),
        }

    def public_dict(self) -> dict[str, Any]:
        """Return endpoint facts without trust/key path disclosure."""

        return {
            "worker_id": self.worker_id,
            "host": self.host,
            "port": self.port,
            "capabilities": list(self.capabilities),
            "concurrency_limit": self.concurrency_limit,
            "connect_timeout": self.connect_timeout or self.timeout,
            "control_timeout": self.control_timeout or self.timeout,
            "execution_timeout_overhead": self.execution_timeout_overhead,
            "labels": dict(self.labels),
            "transport": "tls-mutual-authenticated",
            "registry_membership": "KNOWN",
        }

    def reference_status(self) -> dict[str, Any]:
        missing: list[str] = []
        for field in ("ca_file", "client_certificate", "client_key", "trust_state"):
            path = Path(getattr(self, field)).expanduser()
            if not path.is_file() or path.is_symlink():
                missing.append(field)
        if missing:
            return {
                "outcome": "UNKNOWN",
                "code": "REGISTRY_TRUST_REFERENCE_UNAVAILABLE",
                "detail": "missing or symbolic trust references: " + ", ".join(missing),
            }
        try:
            trust = TrustStore(Path(self.trust_state).expanduser()).lookup("worker", self.worker_id)
        except Exception as exc:
            return {
                "outcome": "UNKNOWN",
                "code": "REGISTRY_TRUST_STATE_INVALID",
                "detail": str(exc),
            }
        if trust is None:
            return {
                "outcome": "UNKNOWN",
                "code": "REGISTRY_WORKER_NOT_ENROLLED",
                "detail": "trust state has no worker enrollment",
            }
        if not trust.get("active"):
            return {
                "outcome": "FAIL",
                "code": "REGISTRY_WORKER_REVOKED",
                "detail": "worker enrollment is revoked",
            }
        return {"outcome": "PASS", "code": "REGISTRY_REFERENCES_READY", "detail": None}

    def to_remote_config(self):
        status = self.reference_status()
        if status["outcome"] != "PASS":
            raise ProtocolError(f"{status['code']}: {status['detail']}")
        from .api import RemoteWorkerConfig

        return RemoteWorkerConfig(
            worker_id=self.worker_id,
            host=self.host,
            port=self.port,
            capabilities=self.capabilities,
            ca_file=Path(self.ca_file).expanduser(),
            client_certificate=Path(self.client_certificate).expanduser(),
            client_key=Path(self.client_key).expanduser(),
            trust_state=Path(self.trust_state).expanduser(),
            concurrency_limit=self.concurrency_limit,
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
            control_timeout=self.control_timeout,
            execution_timeout_overhead=self.execution_timeout_overhead,
        )


class WorkerRegistry:
    """Durable local catalog with explicit mutation and bounded validation."""

    def __init__(self, path: Path, controller_id: str | None = None) -> None:
        self.path = Path(path).expanduser()
        self.controller_id = (
            _text(controller_id, "controller_id", 256)
            if controller_id is not None
            else None
        )

    def _read_unlocked(self) -> tuple[str, tuple[RegistryWorker, ...]]:
        if not self.path.exists():
            if self.controller_id is None:
                raise StorageError("worker registry does not exist and controller_id is unknown")
            return self.controller_id, ()
        if self.path.is_symlink() or not self.path.is_file():
            raise StorageError("worker registry must be a regular non-symbolic file")
        raw = self.path.read_bytes()
        if len(raw) > MAX_REGISTRY_BYTES:
            raise StorageError("worker registry exceeds the bounded size")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError(f"worker registry is malformed: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {"schema_version", "controller_id", "workers"}:
            raise ValidationError("worker registry has an unexpected field set")
        if value.get("schema_version") != WORKER_REGISTRY_SCHEMA:
            raise ValidationError("worker registry uses an unsupported schema version")
        controller_id = _text(value.get("controller_id"), "controller_id", 256)
        if self.controller_id is not None and controller_id != self.controller_id:
            raise ValidationError("worker registry controller identity does not match consumer")
        raw_workers = value.get("workers")
        if not isinstance(raw_workers, list) or len(raw_workers) > MAX_REGISTRY_WORKERS:
            raise ValidationError("worker registry worker list is invalid or oversized")
        workers = tuple(RegistryWorker.from_dict(item) for item in raw_workers if isinstance(item, dict))
        if len(workers) != len(raw_workers):
            raise ValidationError("worker registry entries must be objects")
        identities = [worker.worker_id for worker in workers]
        endpoints = [(worker.host.casefold(), worker.port) for worker in workers]
        if len(set(identities)) != len(identities):
            raise ValidationError("worker registry contains a duplicate worker identity")
        if len(set(endpoints)) != len(endpoints):
            raise ValidationError("worker registry maps one endpoint to conflicting identities")
        return controller_id, tuple(sorted(workers, key=lambda item: item.worker_id))

    def load(self) -> tuple[RegistryWorker, ...]:
        with _exclusive_lock(self.path):
            _controller_id, workers = self._read_unlocked()
        return workers

    def validate(self) -> dict[str, Any]:
        try:
            with _exclusive_lock(self.path):
                controller_id, workers = self._read_unlocked()
        except (OSError, StorageError, ValidationError) as exc:
            return {
                "schema_version": WORKER_REGISTRY_SCHEMA,
                "outcome": "FAIL",
                "code": "REGISTRY_INVALID",
                "detail": str(exc),
                "workers": [],
            }
        statuses = [
            {**worker.public_dict(), "reference_status": worker.reference_status()}
            for worker in workers
        ]
        outcomes = {item["reference_status"]["outcome"] for item in statuses}
        outcome = "FAIL" if "FAIL" in outcomes else "UNKNOWN" if "UNKNOWN" in outcomes else "PASS"
        return {
            "schema_version": WORKER_REGISTRY_SCHEMA,
            "controller_id": controller_id,
            "outcome": outcome,
            "code": "REGISTRY_READY" if outcome == "PASS" else "REGISTRY_REQUIRES_ATTENTION",
            "detail": None,
            "worker_count": len(statuses),
            "workers": statuses,
        }

    def _write_unlocked(self, controller_id: str, workers: Iterable[RegistryWorker]) -> None:
        ordered = sorted(workers, key=lambda item: item.worker_id)
        value = {
            "schema_version": WORKER_REGISTRY_SCHEMA,
            "controller_id": controller_id,
            "workers": [worker.to_dict() for worker in ordered],
        }
        encoded = canonical_json_bytes(value) + b"\n"
        if len(encoded) > MAX_REGISTRY_BYTES:
            raise StorageError("worker registry exceeds the bounded size")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def register(self, worker: RegistryWorker) -> dict[str, Any]:
        status = worker.reference_status()
        if status["outcome"] != "PASS":
            raise ProtocolError(f"{status['code']}: {status['detail']}")
        with _exclusive_lock(self.path):
            controller_id, workers = self._read_unlocked()
            if any(item.worker_id == worker.worker_id for item in workers):
                raise ProtocolError(f"worker is already in the registry: {worker.worker_id}")
            if any(
                item.host.casefold() == worker.host.casefold() and item.port == worker.port
                for item in workers
            ):
                raise ProtocolError("registry endpoint is already bound to another worker")
            self._write_unlocked(controller_id, (*workers, worker))
        return {"outcome": "PASS", "action": "REGISTERED", **worker.public_dict()}

    def update(self, worker: RegistryWorker) -> dict[str, Any]:
        status = worker.reference_status()
        if status["outcome"] != "PASS":
            raise ProtocolError(f"{status['code']}: {status['detail']}")
        with _exclusive_lock(self.path):
            controller_id, workers = self._read_unlocked()
            if not any(item.worker_id == worker.worker_id for item in workers):
                raise ProtocolError(f"worker is not in the registry: {worker.worker_id}")
            if any(
                item.worker_id != worker.worker_id
                and item.host.casefold() == worker.host.casefold()
                and item.port == worker.port
                for item in workers
            ):
                raise ProtocolError("registry endpoint is already bound to another worker")
            revised = tuple(worker if item.worker_id == worker.worker_id else item for item in workers)
            self._write_unlocked(controller_id, revised)
        return {"outcome": "PASS", "action": "UPDATED", **worker.public_dict()}

    def remove(self, worker_id: str) -> dict[str, Any]:
        _text(worker_id, "worker_id", 256)
        with _exclusive_lock(self.path):
            controller_id, workers = self._read_unlocked()
            revised = tuple(item for item in workers if item.worker_id != worker_id)
            if len(revised) == len(workers):
                raise ProtocolError(f"worker is not in the registry: {worker_id}")
            self._write_unlocked(controller_id, revised)
        return {"outcome": "PASS", "action": "REMOVED", "worker_id": worker_id}
