"""Bounded native transfer and immutable cache for EA-NEXT-002 bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .bundles import MAX_ARCHIVE_BYTES, BundleReport, verify_bundle_archive
from .canonical import canonical_json_bytes, is_sha256_identity, sha256_identity
from .errors import ProtocolError, StorageError
from .io import write_json
from .node import utc_now
from .protocol import make_envelope


TRANSFER_SCHEMA = "mncs-fabric.bundle-transfer.v0.1"
MAX_CHUNK_BYTES = 64 * 1024
MAX_CHUNKS = 2048
MAX_IN_PROGRESS = 4
MAX_CACHE_BYTES = 256 * 1024 * 1024


def _raw_identity(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


class BundleCache:
    """Publish verified bundles atomically and expose only complete roots."""

    def __init__(self, root: Path, *, max_cache_bytes: int = MAX_CACHE_BYTES) -> None:
        self.root = Path(root)
        self.bundle_root = self.root / "bundles"
        self.staging_root = self.root / ".staging"
        self.bundle_root.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        if max_cache_bytes < 1:
            raise ValueError("max_cache_bytes must be positive")
        self.max_cache_bytes = min(max_cache_bytes, MAX_CACHE_BYTES)

    def _target(self, bundle_identity: str) -> Path:
        if not _raw_identity(bundle_identity):
            raise ProtocolError("bundle identity must be a raw SHA-256")
        return self.bundle_root / bundle_identity

    def _state(self, transfer_id: str) -> Path:
        safe = hashlib.sha256(transfer_id.encode("utf-8")).hexdigest()
        return self.staging_root / safe

    def _cache_bytes(self) -> int:
        total = 0
        for path in self.bundle_root.rglob("*"):
            if path.is_file():
                total += path.stat().st_size
        return total

    def _published_metadata(self, target: Path) -> dict[str, Any] | None:
        metadata = target / "metadata.json"
        if not metadata.is_file():
            return None
        try:
            value = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise StorageError("published bundle metadata is corrupt")
        if not isinstance(value, dict) or value.get("schema_version") != TRANSFER_SCHEMA:
            raise StorageError("published bundle metadata uses an unsupported version")
        return value

    def begin(self, *, transfer_id: str, bundle_identity: str, archive_identity: str, total_bytes: int, chunk_bytes: int, chunk_count: int) -> str:
        if not transfer_id or not is_sha256_identity(archive_identity) or not _raw_identity(bundle_identity):
            raise ProtocolError("bundle transfer identities are invalid")
        if not 1 <= total_bytes <= MAX_ARCHIVE_BYTES or not 1 <= chunk_bytes <= MAX_CHUNK_BYTES or not 1 <= chunk_count <= MAX_CHUNKS or chunk_count != (total_bytes + chunk_bytes - 1) // chunk_bytes:
            raise ProtocolError("bundle transfer bounds are invalid")
        target = self._target(bundle_identity)
        published = self._published_metadata(target) if target.exists() else None
        if published is not None:
            if published.get("archive_identity") != archive_identity:
                raise ProtocolError("logical bundle identity is already bound to different archive bytes")
            return "ALREADY_PRESENT"
        if len([path for path in self.staging_root.iterdir() if path.is_dir()]) >= MAX_IN_PROGRESS:
            raise ProtocolError("bundle transfer concurrency limit exhausted")
        state = self._state(transfer_id)
        if state.exists():
            metadata = self._published_metadata(state)
            if metadata is not None and metadata.get("archive_identity") != archive_identity:
                raise ProtocolError("transfer identity is bound to different archive bytes")
            return "TRANSFER_REQUIRED"
        state.mkdir(mode=0o700)
        write_json(state / "state.json", {"schema_version": TRANSFER_SCHEMA, "transfer_id": transfer_id, "bundle_identity": bundle_identity, "archive_identity": archive_identity, "total_bytes": total_bytes, "chunk_bytes": chunk_bytes, "chunk_count": chunk_count, "next_sequence": 0, "received_bytes": 0})
        (state / "archive.part").touch(mode=0o600)
        return "TRANSFER_REQUIRED"

    def chunk(self, *, transfer_id: str, bundle_identity: str, archive_identity: str, sequence: int, data: bytes) -> str:
        state = self._state(transfer_id)
        if not state.is_dir():
            raise ProtocolError("bundle transfer is unknown")
        state_file = state / "state.json"
        try:
            metadata = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise StorageError("bundle transfer state is corrupt") from exc
        if metadata.get("bundle_identity") != bundle_identity or metadata.get("archive_identity") != archive_identity:
            raise ProtocolError("bundle chunk identity does not match transfer")
        if sequence != metadata.get("next_sequence") or not 0 < len(data) <= metadata.get("chunk_bytes", 0):
            raise ProtocolError("bundle chunk sequence or size is invalid")
        if metadata["received_bytes"] + len(data) > metadata["total_bytes"]:
            raise ProtocolError("bundle chunk exceeds declared archive size")
        with (state / "archive.part").open("ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        metadata["next_sequence"] += 1
        metadata["received_bytes"] += len(data)
        write_json(state_file, metadata)
        return "ACCEPTED"

    def commit(self, *, transfer_id: str, bundle_identity: str, archive_identity: str) -> tuple[str, BundleReport | None, Path | None]:
        state = self._state(transfer_id)
        if not state.is_dir():
            raise ProtocolError("bundle transfer is unknown")
        metadata = json.loads((state / "state.json").read_text(encoding="utf-8"))
        if metadata.get("bundle_identity") != bundle_identity or metadata.get("archive_identity") != archive_identity:
            raise ProtocolError("bundle commit identity does not match transfer")
        if metadata.get("received_bytes") != metadata.get("total_bytes") or metadata.get("next_sequence") != metadata.get("chunk_count"):
            raise ProtocolError("bundle commit occurred before all chunks arrived")
        archive = state / "archive.part"
        if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_identity[7:]:
            return "FAIL", None, None
        report = verify_bundle_archive(archive, expected_bundle_identity=bundle_identity, expected_archive_identity=archive_identity)
        if not report.valid:
            return report.category, report, None
        target = self._target(bundle_identity)
        published = self._published_metadata(target) if target.exists() else None
        if published is not None:
            if published.get("archive_identity") != archive_identity:
                raise ProtocolError("published logical bundle identity is substituted")
            shutil.rmtree(state)
            return "ALREADY_PRESENT", report, target / "content"
        if self._cache_bytes() + archive.stat().st_size > self.max_cache_bytes:
            return "UNKNOWN", None, None
        publish_parent = self.bundle_root
        temporary = Path(tempfile.mkdtemp(prefix=".publish-", dir=publish_parent))
        try:
            content = temporary / "content"
            content.mkdir()
            with zipfile.ZipFile(archive, "r") as source:
                entries = report.manifest.get("entries", []) if report.manifest else []
                for entry in entries:
                    name = entry["path"]
                    destination = content / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source.open(name, "r") as source_stream, destination.open("xb") as destination_stream:
                        shutil.copyfileobj(source_stream, destination_stream, length=64 * 1024)
                    os.chmod(destination, int(entry["mode"], 8))
            shutil.copyfile(archive, temporary / "archive.zip")
            write_json(temporary / "metadata.json", {"schema_version": TRANSFER_SCHEMA, "bundle_identity": bundle_identity, "archive_identity": archive_identity, "content_bytes": sum(path.stat().st_size for path in (temporary / "content").rglob("*" ) if path.is_file())})
            os.replace(temporary, target)
            shutil.rmtree(state)
            return "COMMITTED", report, target / "content"
        except FileExistsError:
            shutil.rmtree(temporary, ignore_errors=True)
            published = self._published_metadata(target)
            if published and published.get("archive_identity") == archive_identity:
                shutil.rmtree(state, ignore_errors=True)
                return "ALREADY_PRESENT", report, target / "content"
            raise ProtocolError("bundle publication raced with a conflicting identity")
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    def root_for(self, bundle_identity: str, archive_identity: str) -> Path:
        target = self._target(bundle_identity)
        metadata = self._published_metadata(target)
        if metadata is None or metadata.get("archive_identity") != archive_identity:
            raise ProtocolError("requested bundle is not available in the immutable cache")
        archive = target / "archive.zip"
        report = verify_bundle_archive(archive, expected_bundle_identity=bundle_identity, expected_archive_identity=archive_identity)
        if not report.valid or not (target / "content").is_dir():
            raise StorageError("published bundle cache entry failed verification")
        return target / "content"

    def report_for(self, bundle_identity: str, archive_identity: str) -> BundleReport:
        root = self.root_for(bundle_identity, archive_identity)
        return verify_bundle_archive(root.parent / "archive.zip", expected_bundle_identity=bundle_identity, expected_archive_identity=archive_identity)


def _bundle_envelope(message_type: str, *, controller_id: str, worker_id: str, request_id: str, transfer_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    created = utc_now()
    from datetime import datetime, timedelta, timezone
    expires = (datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    return make_envelope(message_type, controller_id=controller_id, worker_id=worker_id, request_id=request_id, job_id="bundle:" + transfer_id, nonce="bundle-" + sha256_identity({"transfer_id": transfer_id, "request_id": request_id})[7:55], payload=payload, created_at=created, expires_at=expires)


def transfer_archive(transport: Any, *, controller_id: str, worker_id: str, archive: Path, expected_bundle_identity: str | None = None) -> dict[str, Any]:
    """Transfer one verified archive over an existing Fabric envelope transport."""

    report = verify_bundle_archive(archive, expected_bundle_identity=expected_bundle_identity)
    if not report.valid or report.bundle_identity is None or report.archive_identity is None:
        raise ProtocolError("controller will not transfer an unverified execution bundle")
    total_bytes = archive.stat().st_size
    chunk_bytes = MAX_CHUNK_BYTES
    chunk_count = (total_bytes + chunk_bytes - 1) // chunk_bytes
    transfer_id = "transfer-" + sha256_identity({"bundle_identity": report.bundle_identity, "archive_identity": report.archive_identity})[7:39]
    base = {"transfer_schema": TRANSFER_SCHEMA, "transfer_id": transfer_id, "bundle_identity": report.bundle_identity, "archive_identity": report.archive_identity, "total_bytes": total_bytes, "chunk_bytes": chunk_bytes, "chunk_count": chunk_count}
    response = transport.request(_bundle_envelope("bundle.offer", controller_id=controller_id, worker_id=worker_id, request_id=transfer_id + ":offer", transfer_id=transfer_id, payload=base))
    status = response.get("payload", {}).get("status")
    if status == "ALREADY_PRESENT":
        return {"status": status, **report.as_dict(), "transfer_id": transfer_id}
    if status != "TRANSFER_REQUIRED":
        raise ProtocolError("worker rejected bundle offer")
    with archive.open("rb") as stream:
        for sequence in range(chunk_count):
            data = stream.read(chunk_bytes)
            payload = {**base, "sequence": sequence, "data": base64.b64encode(data).decode("ascii")}
            chunk_response = transport.request(_bundle_envelope("bundle.chunk", controller_id=controller_id, worker_id=worker_id, request_id=f"{transfer_id}:chunk:{sequence}", transfer_id=transfer_id, payload=payload))
            if chunk_response.get("payload", {}).get("status") != "ACCEPTED":
                raise ProtocolError("worker rejected bundle chunk")
    commit = transport.request(_bundle_envelope("bundle.commit", controller_id=controller_id, worker_id=worker_id, request_id=transfer_id + ":commit", transfer_id=transfer_id, payload=base))
    commit_status = commit.get("payload", {}).get("status")
    if commit_status not in {"COMMITTED", "ALREADY_PRESENT"}:
        raise ProtocolError("worker did not publish the verified bundle")
    return {"status": commit_status, **report.as_dict(), "transfer_id": transfer_id}
