"""Small Fabric-owned append-only JSONL ledger with explicit recovery."""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from .canonical import canonical_json_bytes, sha256_identity
from .errors import StorageError

LEDGER_SCHEMA = "mncs-fabric.ledger.v0.1"


@dataclass(frozen=True)
class LedgerDiagnostic:
    code: str
    message: str
    line: int | None = None


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 30.0
    handle: BinaryIO | None = None
    while True:
        candidate: BinaryIO | None = None
        try:
            candidate = lock_path.open("a+b", buffering=0)
            if os.name == "nt":
                import msvcrt

                # Lock one stable byte.  The file may grow during a racy
                # first creation, but every holder uses byte zero.
                candidate.seek(0, os.SEEK_END)
                if candidate.tell() == 0:
                    candidate.write(b"\0")
                    candidate.flush()
                candidate.seek(0)
                msvcrt.locking(candidate.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(candidate.fileno(), fcntl.LOCK_EX)
            handle = candidate
            break
        except PermissionError:
            if candidate is not None:
                candidate.close()
            if os.name != "nt" or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)

    assert handle is not None
    try:
        yield
    finally:
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                # Windows releases the region when this exact handle closes.
                # Explicit LK_UNLCK is unreliable on hosted Windows runners.
                handle.flush()
        finally:
            # Handle closure must happen even when release/flush reports an
            # error, otherwise the lock file remains undeletable on Windows.
            handle.close()


class FabricLedger:
    """Append immutable records; repair is explicit and only applies to a tail."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read_unlocked(self) -> tuple[list[dict[str, Any]], list[LedgerDiagnostic], bool]:
        if not self.path.exists():
            return [], [], False
        raw = self.path.read_bytes()
        if not raw:
            return [], [], False
        trailing_partial = not raw.endswith(b"\n")
        lines = raw.splitlines()
        records: list[dict[str, Any]] = []
        diagnostics: list[LedgerDiagnostic] = []
        for index, line in enumerate(lines, 1):
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                if trailing_partial and index == len(lines):
                    diagnostics.append(LedgerDiagnostic("TRUNCATED_TAIL", str(exc), index))
                    continue
                raise StorageError(f"ledger line {index} is corrupt: {exc}") from exc
            if not isinstance(value, dict):
                raise StorageError(f"ledger line {index} is not an object")
            self._validate_entry(value, records[-1] if records else None, index)
            records.append(value)
        if trailing_partial and records and not diagnostics:
            diagnostics.append(LedgerDiagnostic("TRAILING_NEWLINE_MISSING", "valid final ledger entry is missing its newline", len(records)))
        return records, diagnostics, trailing_partial

    @staticmethod
    def _validate_entry(value: dict[str, Any], previous: dict[str, Any] | None, line: int) -> None:
        if value.get("schema_version") != LEDGER_SCHEMA:
            raise StorageError(f"ledger line {line} uses an unsupported schema version")
        required = {"schema_version", "sequence", "previous_identity", "record_type", "record", "record_identity", "entry_identity"}
        if set(value) != required:
            raise StorageError(f"ledger line {line} has an unexpected field set")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or sequence != (previous["sequence"] + 1 if previous else 1):
            raise StorageError(f"ledger sequence is invalid at line {line}")
        previous_identity = previous["entry_identity"] if previous else None
        if value.get("previous_identity") != previous_identity:
            raise StorageError(f"ledger hash linkage is invalid at line {line}")
        record = value.get("record")
        if not isinstance(record, dict) or value.get("record_identity") != sha256_identity(record):
            raise StorageError(f"ledger record identity is invalid at line {line}")
        material = {key: item for key, item in value.items() if key != "entry_identity"}
        if value.get("entry_identity") != sha256_identity(material):
            raise StorageError(f"ledger entry identity is invalid at line {line}")

    def verify(self) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            records, diagnostics, _ = self._read_unlocked()
        return {"schema_version": LEDGER_SCHEMA, "record_count": len(records), "diagnostics": [diagnostic.__dict__ for diagnostic in diagnostics], "outcome": "UNKNOWN" if diagnostics else "PASS"}

    def recover(self, *, repair_truncated_tail: bool = False) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            records, diagnostics, partial = self._read_unlocked()
            repaired = False
            if partial and repair_truncated_tail:
                if diagnostics and diagnostics[-1].code == "TRAILING_NEWLINE_MISSING":
                    with self.path.open("ab") as stream:
                        stream.write(b"\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                else:
                    with self.path.open("rb+") as stream:
                        stream.seek(0)
                        data = stream.read()
                        stream.seek(0)
                        stream.write(data[:data.rfind(b"\n") + 1])
                        stream.truncate()
                        stream.flush()
                        os.fsync(stream.fileno())
                repaired = True
        return {"record_count": len(records), "diagnostics": [diagnostic.__dict__ for diagnostic in diagnostics], "repaired": repaired, "outcome": "PASS" if not diagnostics or repaired else "UNKNOWN"}

    def append(self, record_type: str, record: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record_type, str) or not record_type:
            raise StorageError("record_type must be a non-empty string")
        with _exclusive_lock(self.path):
            records, diagnostics, _ = self._read_unlocked()
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            record_identity = sha256_identity(record)
            for existing in records:
                if existing["record_identity"] == record_identity:
                    if existing["record_type"] != record_type or existing["record"] != record:
                        raise StorageError("conflicting duplicate record identity")
                    return existing
            previous = records[-1] if records else None
            entry: dict[str, Any] = {
                "schema_version": LEDGER_SCHEMA,
                "sequence": len(records) + 1,
                "previous_identity": previous["entry_identity"] if previous else None,
                "record_type": record_type,
                "record": record,
                "record_identity": record_identity,
            }
            entry["entry_identity"] = sha256_identity(entry)
            with self.path.open("ab") as stream:
                stream.write(canonical_json_bytes(entry) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            return entry

    def records(self, *, record_type: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or limit < 0 or limit > 100000:
            raise StorageError("ledger read limit is outside the bounded range")
        with _exclusive_lock(self.path):
            records, diagnostics, _ = self._read_unlocked()
        if diagnostics:
            raise StorageError("ledger has an unrepaired truncated tail")
        values = [item for item in records if record_type is None or item["record_type"] == record_type]
        return values[-limit:] if limit else []
