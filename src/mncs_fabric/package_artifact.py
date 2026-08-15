"""Content-addressed Fabric package artifacts.

A desired Fabric version is bound to exact bytes.  Filenames are not trusted.
Transfer reuses the same bounded chunk sizes as execution-bundle transfer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, sha256_identity, verify_identity
from .errors import ProtocolError, ValidationError
from .node import utc_now
from .versioning import parse_fabric_version

PACKAGE_ARTIFACT_SCHEMA = "mncs-fabric.package-artifact.v0.1"
PACKAGE_TRANSFER_SCHEMA = "mncs-fabric.package-artifact-transfer.v0.1"
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_CHUNK_BYTES = 64 * 1024
MAX_CHUNKS = 512
ALLOWED_PACKAGES = frozenset({"mncs-fabric"})


def _text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValidationError(f"{field} must be bounded non-empty text")
    return value


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def describe_package_artifact(
    path: Path,
    *,
    package: str = "mncs-fabric",
    version: str,
    source: str = "operator-staged",
) -> dict[str, Any]:
    artifact = Path(path)
    if not artifact.is_file():
        raise ValidationError("package artifact path is not a file")
    size = artifact.stat().st_size
    if not 1 <= size <= MAX_ARTIFACT_BYTES:
        raise ValidationError("package artifact size is outside the bounded range")
    if parse_fabric_version(version) is None:
        raise ValidationError("package artifact version is malformed")
    if package not in ALLOWED_PACKAGES:
        raise ValidationError("package artifact package is unsupported")
    digest = file_digest(artifact)
    value = {
        "schema_version": PACKAGE_ARTIFACT_SCHEMA,
        "package": package,
        "version": version,
        "digest": digest,
        "size_bytes": size,
        "filename": artifact.name[:256],
        "source": _text(source, "source", 128),
        "captured_at": utc_now(),
        "claim_boundary": "content-addressed package bytes; not provenance attestation or signature",
    }
    return attach_identity(value, "artifact_identity")


def validate_package_artifact(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != PACKAGE_ARTIFACT_SCHEMA:
        raise ValidationError("unsupported package artifact schema")
    required = {
        "schema_version", "package", "version", "digest", "size_bytes", "filename",
        "source", "captured_at", "claim_boundary", "artifact_identity",
    }
    if set(value) != required or not verify_identity(value, "artifact_identity"):
        raise ValidationError("package artifact fields or identity are invalid")
    if value["package"] not in ALLOWED_PACKAGES:
        raise ValidationError("package artifact package is unsupported")
    if parse_fabric_version(str(value["version"])) is None:
        raise ValidationError("package artifact version is malformed")
    digest = value["digest"]
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise ValidationError("package artifact digest is invalid")
    if not isinstance(value["size_bytes"], int) or isinstance(value["size_bytes"], bool) or not 1 <= value["size_bytes"] <= MAX_ARTIFACT_BYTES:
        raise ValidationError("package artifact size is invalid")
    return dict(value)


def verify_package_artifact(path: Path, expected: Mapping[str, Any]) -> dict[str, Any]:
    checked = validate_package_artifact(expected)
    artifact = Path(path)
    if not artifact.is_file():
        raise ValidationError("staged package artifact is missing")
    size = artifact.stat().st_size
    if size != checked["size_bytes"]:
        raise ValidationError("staged package artifact size does not match the descriptor")
    digest = file_digest(artifact)
    if digest != checked["digest"]:
        raise ValidationError("staged package artifact digest does not match the descriptor")
    return checked


def write_artifact_descriptor(directory: Path, artifact: Mapping[str, Any]) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "artifact.json"
    path.write_text(json.dumps(validate_package_artifact(artifact), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_artifact_descriptor(directory: Path) -> dict[str, Any] | None:
    path = Path(directory) / "artifact.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return validate_package_artifact(value)
    except ValidationError:
        return None


def staged_artifact_path(directory: Path, artifact: Mapping[str, Any]) -> Path:
    digest = validate_package_artifact(artifact)["digest"].split(":", 1)[1]
    suffix = ".tar.gz" if str(artifact.get("filename", "")).endswith(".tar.gz") else ".whl"
    return Path(directory) / f"{digest}{suffix}"


def chunk_bounds(size_bytes: int) -> tuple[int, int]:
    if not 1 <= size_bytes <= MAX_ARTIFACT_BYTES:
        raise ValidationError("package artifact size is outside the bounded range")
    chunks = (size_bytes + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES
    if chunks > MAX_CHUNKS:
        raise ValidationError("package artifact requires too many chunks")
    return MAX_CHUNK_BYTES, chunks


def _parse_metadata_headers(raw: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        if not line or line.startswith(" ") or ":" not in line:
            if not line:
                break
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


def inspect_package_metadata(path: Path) -> dict[str, Any]:
    """Read wheel/sdist package name and version without executing package code."""

    artifact = Path(path)
    if not artifact.is_file():
        raise ValidationError("package artifact path is not a file")
    name = artifact.name.lower()
    try:
        if name.endswith(".whl") or zipfile.is_zipfile(artifact):
            with zipfile.ZipFile(artifact) as archive:
                candidates = [item for item in archive.namelist() if item.endswith(".dist-info/METADATA") or item.endswith("PKG-INFO")]
                if not candidates:
                    return {"format": "unrecognized", "package": None, "version": None, "source": None}
                headers = _parse_metadata_headers(archive.read(sorted(candidates)[0]))
                return {
                    "format": "wheel" if name.endswith(".whl") else "zip",
                    "package": headers.get("name"),
                    "version": headers.get("version"),
                    "source": sorted(candidates)[0],
                }
        if name.endswith((".tar.gz", ".tgz")) or tarfile.is_tarfile(artifact):
            with tarfile.open(artifact, "r:*") as archive:
                members = [item for item in archive.getmembers() if item.isfile() and item.name.endswith(("PKG-INFO", "METADATA"))]
                if not members:
                    return {"format": "unrecognized", "package": None, "version": None, "source": None}
                member = sorted(members, key=lambda item: (0 if item.name.endswith("PKG-INFO") else 1, item.name))[0]
                extracted = archive.extractfile(member)
                if extracted is None:
                    return {"format": "unrecognized", "package": None, "version": None, "source": None}
                headers = _parse_metadata_headers(extracted.read(64 * 1024))
                return {
                    "format": "sdist",
                    "package": headers.get("name"),
                    "version": headers.get("version"),
                    "source": member.name,
                }
    except (OSError, tarfile.TarError, zipfile.BadZipFile, UnicodeError) as exc:
        raise ValidationError(f"package metadata could not be inspected: {exc}") from exc
    return {"format": "unrecognized", "package": None, "version": None, "source": None}


def verify_package_metadata(path: Path, expected: Mapping[str, Any]) -> dict[str, Any]:
    """Verify wheel/sdist metadata when the archive is inspectable.

    Unrecognized bytes remain content-addressed; the provenance gap is
    recorded rather than invented.
    """

    checked = validate_package_artifact(expected)
    meta = inspect_package_metadata(path)
    if meta.get("format") == "unrecognized" or not meta.get("package") or not meta.get("version"):
        return {
            "verified": False,
            "format": meta.get("format") or "unrecognized",
            "reason": "bytes are content-addressed but package metadata is not inspectable",
            "package": meta.get("package"),
            "version": meta.get("version"),
        }
    if meta["package"] not in {checked["package"], checked["package"].replace("-", "_")}:
        raise ValidationError(
            f"package metadata name {meta['package']!r} does not match descriptor {checked['package']!r}"
        )
    if meta["version"] != checked["version"]:
        raise ValidationError(
            f"package metadata version {meta['version']!r} does not match descriptor {checked['version']!r}"
        )
    return {
        "verified": True,
        "format": meta["format"],
        "reason": "package metadata matches the artifact descriptor",
        "package": meta["package"],
        "version": meta["version"],
        "source": meta.get("source"),
    }


def previous_dir(directory: Path) -> Path:
    return Path(directory) / "previous"


def retain_previous_artifact(directory: Path) -> dict[str, Any]:
    """Keep the last known-good staged artifact for exact rollback."""

    directory = Path(directory)
    descriptor = read_artifact_descriptor(directory)
    if descriptor is None:
        return {
            "previous_version": None,
            "previous_artifact_identity": None,
            "previous_artifact_path": None,
            "rollback_capability": "partial",
            "reason": "previous artifact identity UNKNOWN; version predates content-addressed storage",
        }
    source = staged_artifact_path(directory, descriptor)
    if not source.is_file():
        return {
            "previous_version": descriptor.get("version"),
            "previous_artifact_identity": None,
            "previous_artifact_path": None,
            "rollback_capability": "partial",
            "reason": "previous artifact descriptor exists but the bytes are missing",
        }
    retained = previous_dir(directory)
    retained.mkdir(parents=True, exist_ok=True)
    dest = retained / source.name
    if source.resolve() != dest.resolve():
        dest.write_bytes(source.read_bytes())
    write_artifact_descriptor(retained, descriptor)
    verify_package_artifact(dest, descriptor)
    return {
        "previous_version": descriptor["version"],
        "previous_artifact_identity": descriptor["artifact_identity"],
        "previous_artifact_path": str(dest),
        "rollback_capability": "exact",
        "reason": "retained the last known-good content-addressed artifact",
    }


def read_previous_artifact(directory: Path) -> dict[str, Any]:
    retained = previous_dir(directory)
    descriptor = read_artifact_descriptor(retained)
    if descriptor is None:
        return retain_previous_artifact(directory) if read_artifact_descriptor(directory) else {
            "previous_version": None,
            "previous_artifact_identity": None,
            "previous_artifact_path": None,
            "rollback_capability": "partial",
            "reason": "previous artifact identity UNKNOWN; version predates content-addressed storage",
        }
    path = staged_artifact_path(retained, descriptor)
    if not path.is_file():
        return {
            "previous_version": descriptor.get("version"),
            "previous_artifact_identity": None,
            "previous_artifact_path": None,
            "rollback_capability": "partial",
            "reason": "retained previous artifact bytes are missing",
        }
    try:
        verify_package_artifact(path, descriptor)
    except ValidationError:
        return {
            "previous_version": descriptor.get("version"),
            "previous_artifact_identity": descriptor.get("artifact_identity"),
            "previous_artifact_path": str(path),
            "rollback_capability": "partial",
            "reason": "retained previous artifact failed digest or size verification",
        }
    return {
        "previous_version": descriptor["version"],
        "previous_artifact_identity": descriptor["artifact_identity"],
        "previous_artifact_path": str(path),
        "rollback_capability": "exact",
        "reason": "previous content-addressed artifact is retained",
    }


def transfer_deadline(*, seconds: float = 300.0) -> str:
    if not 1.0 <= seconds <= 3600.0:
        raise ValidationError("artifact transfer deadline is outside the bounded range")
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return when.isoformat().replace("+00:00", "Z")


def build_transfer_identity(
    *,
    worker_identity: str,
    controller_identity: str,
    artifact_identity: str,
    expected_chunk_count: int,
    expected_total_bytes: int,
) -> str:
    return sha256_identity(
        {
            "schema_version": PACKAGE_TRANSFER_SCHEMA,
            "worker_identity": worker_identity,
            "controller_identity": controller_identity,
            "artifact_identity": artifact_identity,
            "expected_chunk_count": expected_chunk_count,
            "expected_total_bytes": expected_total_bytes,
        }
    )


class ArtifactTransferSession:
    """Identity-bound in-memory transfer with an explicit expected sequence set."""

    def __init__(
        self,
        *,
        worker_identity: str,
        controller_identity: str,
        artifact: Mapping[str, Any],
        transfer_identity: str,
        expected_chunk_count: int,
        expected_total_bytes: int,
        expires_at: str,
    ) -> None:
        checked = validate_package_artifact(artifact)
        if expected_total_bytes != checked["size_bytes"]:
            raise ProtocolError("package artifact offer size does not match the descriptor")
        if not 1 <= expected_chunk_count <= MAX_CHUNKS:
            raise ProtocolError("package artifact chunk count is outside the bound")
        _, bounded = chunk_bounds(checked["size_bytes"])
        if expected_chunk_count != bounded:
            raise ProtocolError("package artifact chunk count does not match the descriptor size")
        if not isinstance(transfer_identity, str) or not transfer_identity.startswith("sha256:"):
            raise ProtocolError("package artifact transfer identity is invalid")
        self.worker_identity = worker_identity
        self.controller_identity = controller_identity
        self.artifact = checked
        self.transfer_identity = transfer_identity
        self.expected_chunk_count = expected_chunk_count
        self.expected_total_bytes = expected_total_bytes
        self.expires_at = expires_at
        self.expected_sequences = set(range(expected_chunk_count))
        self._chunks: dict[int, bytes] = {}

    @property
    def received_sequences(self) -> set[int]:
        return set(self._chunks)

    def is_expired(self, now: str | None = None) -> bool:
        stamp = now or utc_now()
        return stamp > self.expires_at

    def _require_active(self, *, transfer_identity: str | None = None, now: str | None = None) -> None:
        if self.is_expired(now):
            raise ProtocolError("package artifact transfer session has expired")
        if transfer_identity is not None and transfer_identity != self.transfer_identity:
            raise ProtocolError("package artifact transfer identity does not match the open session")

    def same_offer(
        self,
        *,
        worker_identity: str,
        controller_identity: str,
        artifact_identity: str,
        transfer_identity: str,
    ) -> bool:
        return (
            self.worker_identity == worker_identity
            and self.controller_identity == controller_identity
            and self.artifact["artifact_identity"] == artifact_identity
            and self.transfer_identity == transfer_identity
        )

    def accept_chunk(
        self,
        *,
        sequence: int,
        data: bytes,
        transfer_identity: str | None = None,
        now: str | None = None,
    ) -> None:
        self._require_active(transfer_identity=transfer_identity, now=now)
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence not in self.expected_sequences:
            raise ProtocolError("package artifact chunk sequence is outside the expected set")
        if not isinstance(data, (bytes, bytearray)) or not 1 <= len(data) <= MAX_CHUNK_BYTES:
            raise ProtocolError("package artifact chunk exceeds its bound")
        if sequence == self.expected_chunk_count - 1:
            remaining = self.expected_total_bytes - (self.expected_chunk_count - 1) * MAX_CHUNK_BYTES
            if len(data) != remaining:
                raise ProtocolError("package artifact final chunk size does not match the descriptor")
        elif len(data) != MAX_CHUNK_BYTES:
            raise ProtocolError("package artifact chunk size does not match the transfer bound")
        existing = self._chunks.get(sequence)
        if existing is not None:
            if existing == bytes(data):
                return
            raise ProtocolError("package artifact chunk conflicts with a previously accepted sequence")
        self._chunks[sequence] = bytes(data)
        if sum(len(item) for item in self._chunks.values()) > self.expected_total_bytes:
            raise ProtocolError("package artifact transfer exceeded the offered size")

    def assembled_bytes(self, *, transfer_identity: str | None = None, now: str | None = None) -> bytes:
        self._require_active(transfer_identity=transfer_identity, now=now)
        missing = self.expected_sequences - self.received_sequences
        if missing:
            raise ProtocolError("package artifact commit is missing required sequences")
        extra = self.received_sequences - self.expected_sequences
        if extra:
            raise ProtocolError("package artifact commit includes sequences outside the expected set")
        blob = b"".join(self._chunks[index] for index in range(self.expected_chunk_count))
        if len(blob) != self.expected_total_bytes:
            raise ProtocolError("package artifact commit size does not match the descriptor")
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        if digest != self.artifact["digest"]:
            raise ProtocolError("package artifact commit digest does not match the descriptor")
        return blob

    def clear(self) -> None:
        self._chunks.clear()


def decode_chunk_data(value: object) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("package artifact chunk is invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("package artifact chunk is not canonical base64") from exc


def write_verified_artifact(directory: Path, artifact: Mapping[str, Any], blob: bytes) -> Path:
    """Write bytes to a .part file; promote only after digest verification."""

    checked = validate_package_artifact(artifact)
    if len(blob) != checked["size_bytes"]:
        raise ValidationError("staged package artifact size does not match the descriptor")
    target = staged_artifact_path(directory, checked)
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = read_artifact_descriptor(directory)
    if existing is not None and existing.get("artifact_identity") != checked["artifact_identity"]:
        retain_previous_artifact(directory)
    temporary = target.with_name(target.name + ".part")
    temporary.write_bytes(blob)
    try:
        verify_package_artifact(temporary, checked)
        verify_package_metadata(temporary, checked)
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    write_artifact_descriptor(directory, checked)
    return target
