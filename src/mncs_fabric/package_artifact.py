"""Content-addressed Fabric package artifacts.

A desired Fabric version is bound to exact bytes.  Filenames are not trusted.
Transfer reuses the same bounded chunk sizes as execution-bundle transfer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import attach_identity, verify_identity
from .errors import ValidationError
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
