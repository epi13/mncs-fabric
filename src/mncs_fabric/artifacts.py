from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Iterable

from .canonical import attach_identity, is_sha256_identity, verify_identity
from .errors import IntegrityError, ValidationError
from .models import MANIFEST_SCHEMA, safe_relative_path

_CHUNK = 1024 * 1024


def file_identity(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, "sha256:" + digest.hexdigest()


def _iter_regular_files(root: Path) -> Iterable[Path]:
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            candidate = current_path / name
            if candidate.is_symlink():
                raise ValidationError(f"symbolic-link directory is not allowed: {candidate}")
        for name in filenames:
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise ValidationError(f"only regular files are allowed: {candidate}")
            yield candidate


def build_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValidationError("artifact root must be a directory")
    entries = []
    for path in sorted(_iter_regular_files(root), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        size, identity = file_identity(path)
        entries.append({"path": relative, "size": size, "sha256": identity})
    manifest = {"schema_version": MANIFEST_SCHEMA, "files": entries}
    return attach_identity(manifest, "manifest_identity")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValidationError(f"manifest schema_version must be {MANIFEST_SCHEMA}")
    if not verify_identity(manifest, "manifest_identity"):
        raise IntegrityError("artifact manifest identity does not verify")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValidationError("manifest files must be an array")
    seen: set[str] = set()
    normalized = []
    for entry in files:
        if not isinstance(entry, dict):
            raise ValidationError("manifest file entries must be objects")
        path = safe_relative_path(entry.get("path"), "manifest files[].path")
        if path in seen:
            raise ValidationError(f"duplicate manifest path: {path}")
        seen.add(path)
        size = entry.get("size")
        identity = entry.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValidationError(f"invalid size for manifest path {path}")
        if not is_sha256_identity(identity):
            raise ValidationError(f"invalid sha256 identity for manifest path {path}")
        normalized.append({"path": path, "size": size, "sha256": identity})
    if normalized != sorted(normalized, key=lambda item: item["path"]):
        raise ValidationError("manifest files must be ordered by path")
    result = dict(manifest)
    result["files"] = normalized
    return result


def verify_manifest(root: Path, manifest: Any, *, reject_extras: bool = True) -> dict[str, Any]:
    root = root.resolve(strict=True)
    declared = validate_manifest(manifest)
    expected_paths = {entry["path"] for entry in declared["files"]}
    observed_paths = {path.relative_to(root).as_posix() for path in _iter_regular_files(root)}
    if reject_extras and observed_paths != expected_paths:
        missing = sorted(expected_paths - observed_paths)
        extras = sorted(observed_paths - expected_paths)
        raise IntegrityError(f"artifact path set differs; missing={missing}, extras={extras}")
    for entry in declared["files"]:
        path = (root / entry["path"]).resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise IntegrityError(f"artifact escaped root: {entry['path']}") from exc
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"artifact is not a regular file: {entry['path']}")
        size, identity = file_identity(path)
        if size != entry["size"] or identity != entry["sha256"]:
            raise IntegrityError(f"artifact identity mismatch: {entry['path']}")
    return declared


def copy_manifest_files(source: Path, destination: Path, manifest: dict[str, Any]) -> None:
    source = source.resolve(strict=True)
    destination.mkdir(parents=True, exist_ok=True)
    for entry in manifest["files"]:
        src = (source / entry["path"]).resolve(strict=True)
        src.relative_to(source)
        dst = destination / entry["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        with src.open("rb") as input_stream, dst.open("xb") as output_stream:
            while chunk := input_stream.read(_CHUNK):
                output_stream.write(chunk)
