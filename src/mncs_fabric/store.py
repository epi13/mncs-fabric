"""Small Fabric-owned append-only JSONL ledger with explicit recovery."""

from __future__ import annotations

import collections
import json
import os
import sqlite3
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator

from .canonical import canonical_json_bytes, sha256_identity
from .errors import StorageError

LEDGER_SCHEMA = "mncs-fabric.ledger.v0.1"
COMPACTION_SCHEMA = "mncs-fabric.ledger-compaction.v0.1"
INDEX_SCHEMA = "mncs-fabric.ledger-index.v0.1"
_INDEX_BATCH_SIZE = 512


def _digest_bytes(identity: str) -> bytes:
    if isinstance(identity, str) and identity.startswith("sha256:") and len(identity) == 71:
        try:
            return bytes.fromhex(identity[7:])
        except ValueError:
            pass
    return str(identity).encode("utf-8")


@dataclass(frozen=True)
class LedgerDiagnostic:
    code: str
    message: str
    line: int | None = None


def iter_ledger_records(
    ledger: "FabricLedger", *, record_type: str | None = None
) -> Iterator[dict[str, Any]]:
    """Use streaming ledger reads while supporting legacy test adapters."""

    iterator = getattr(ledger, "iter_records", None)
    if callable(iterator):
        yield from iterator(record_type=record_type)
    else:
        # Older injected ledger adapters expose only all_records(). They are
        # compatibility shims; the production FabricLedger path is streaming.
        yield from ledger.all_records(record_type=record_type)


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
    """Append immutable records; repair is explicit and only applies to a tail.

    Validation is streaming and memory-bounded: verification checks the full
    hash-chain without retaining historical records in RAM.  Bounded metadata
    (size, mtime_ns, sequence, head identity) is memoized on the ledger file's
    stat token.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._index_path = self.path.with_name(self.path.name + ".idx")
        self._verified_token: tuple[int, int] | None = None
        self._full_audit_token: tuple[int, int] | None = None
        self._record_count: int = 0
        self._last_entry: dict[str, Any] | None = None
        self._diagnostics: list[LedgerDiagnostic] = []
        self._partial: bool = False

    def _remove_index_unlocked(self) -> None:
        try:
            self._index_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _connect_index_unlocked(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._index_path, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=MEMORY")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute("PRAGMA temp_store=MEMORY")
        except BaseException:
            conn.close()
            raise
        return conn

    @staticmethod
    def _init_index_tables(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version TEXT NOT NULL,
                ledger_size INTEGER NOT NULL,
                record_count INTEGER NOT NULL,
                first_offset INTEGER NOT NULL,
                first_length INTEGER NOT NULL,
                first_entry_id TEXT NOT NULL,
                prev_entry_id TEXT,
                last_offset INTEGER NOT NULL,
                last_length INTEGER NOT NULL,
                last_entry_id TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                seq INTEGER PRIMARY KEY,
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                record_type TEXT NOT NULL,
                record_id BLOB NOT NULL
            )
            """
        )

    @staticmethod
    def _init_index_indexes(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_record_id ON entries(record_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_type_seq ON entries(record_type, seq)")

    @classmethod
    def _init_index_schema(cls, conn: sqlite3.Connection) -> None:
        cls._init_index_tables(conn)
        cls._init_index_indexes(conn)

    def _read_entry_at_unlocked(self, offset: int, length: int, *, line_hint: int = 1) -> dict[str, Any]:
        if offset < 0 or length <= 0 or not self.path.exists():
            raise StorageError(f"ledger line {line_hint} offset is invalid")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            raw = stream.read(length)
        if len(raw) != length or not raw.endswith(b"\n"):
            raise StorageError(f"ledger line {line_hint} is truncated or misaligned")
        stripped = raw.rstrip(b"\r\n")
        if not stripped:
            raise StorageError(f"ledger line {line_hint} is empty")
        try:
            value = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageError(f"ledger line {line_hint} is corrupt: {exc}") from exc
        if not isinstance(value, dict):
            raise StorageError(f"ledger line {line_hint} is not an object")
        if value.get("schema_version") != LEDGER_SCHEMA:
            raise StorageError(f"ledger line {line_hint} uses an unsupported schema version")
        required = {
            "schema_version",
            "sequence",
            "previous_identity",
            "record_type",
            "record",
            "record_identity",
            "entry_identity",
        }
        if set(value) != required:
            raise StorageError(f"ledger line {line_hint} has an unexpected field set")
        record = value.get("record")
        if not isinstance(record, dict) or value.get("record_identity") != sha256_identity(record):
            raise StorageError(f"ledger record identity is invalid at line {line_hint}")
        material = {key: item for key, item in value.items() if key != "entry_identity"}
        if value.get("entry_identity") != sha256_identity(material):
            raise StorageError(f"ledger entry identity is invalid at line {line_hint}")
        return value

    def _sync_from_index_unlocked(
        self, stat: os.stat_result, token: tuple[int, int]
    ) -> tuple[int, dict[str, Any] | None, list[LedgerDiagnostic], bool] | None:
        if not self._index_path.exists():
            return None
        try:
            with closing(self._connect_index_unlocked()) as conn:
                row = conn.execute(
                    """
                    SELECT schema_version, ledger_size, record_count,
                           first_offset, first_length, first_entry_id,
                           prev_entry_id, last_offset, last_length, last_entry_id
                    FROM meta WHERE id = 1
                    """
                ).fetchone()
                if row is None:
                    return None
                (
                    schema_version,
                    ledger_size,
                    record_count,
                    first_offset,
                    first_length,
                    first_entry_id,
                    prev_entry_id,
                    last_offset,
                    last_length,
                    last_entry_id,
                ) = row
                if (
                    schema_version != INDEX_SCHEMA
                    or not isinstance(record_count, int)
                    or record_count < 1
                    or first_offset != 0
                    or first_length <= 0
                    or last_length <= 0
                    or last_offset + last_length != ledger_size
                    or ledger_size <= 0
                    or stat.st_size < ledger_size
                ):
                    return None
                first_entry = self._read_entry_at_unlocked(0, first_length, line_hint=1)
                self._validate_entry_fast(first_entry, 0, None, 1)
                if first_entry.get("entry_identity") != first_entry_id:
                    return None
                if record_count == 1:
                    if prev_entry_id is not None or last_offset != 0 or last_length != first_length:
                        return None
                    tail_entry = first_entry
                else:
                    tail_entry = self._read_entry_at_unlocked(last_offset, last_length, line_hint=record_count)
                    self._validate_entry_fast(tail_entry, record_count - 1, prev_entry_id, record_count)
                    if tail_entry.get("entry_identity") != last_entry_id:
                        return None

                if stat.st_size == ledger_size:
                    self._verified_token = token
                    self._record_count = record_count
                    self._last_entry = tail_entry
                    self._diagnostics = []
                    self._partial = False
                    return record_count, tail_entry, [], False

                # Incremental scan of new bytes appended after ledger_size
                count = record_count
                previous_sequence = record_count
                previous_entry_identity: str | None = str(last_entry_id)
                prev_for_last: str | None = prev_entry_id
                last_entry: dict[str, Any] | None = tail_entry
                diagnostics: list[LedgerDiagnostic] = []
                trailing_partial = False
                new_rows: list[tuple[int, int, int, str, bytes]] = []
                cur_offset = int(ledger_size)
                cur_last_offset = int(last_offset)
                cur_last_length = int(last_length)

                with self.path.open("rb") as stream:
                    stream.seek(ledger_size)
                    line_number = record_count
                    for line in stream:
                        line_number += 1
                        line_len = len(line)
                        trailing_partial = not line.endswith(b"\n")
                        stripped = line.rstrip(b"\r\n")
                        if not stripped:
                            if trailing_partial:
                                diagnostics.append(
                                    LedgerDiagnostic("TRUNCATED_TAIL", "empty line in partial tail", line_number)
                                )
                                break
                            raise StorageError(f"ledger line {line_number} is empty")
                        try:
                            value = json.loads(stripped.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            if trailing_partial:
                                diagnostics.append(LedgerDiagnostic("TRUNCATED_TAIL", str(exc), line_number))
                                break
                            raise StorageError(f"ledger line {line_number} is corrupt: {exc}") from exc
                        if not isinstance(value, dict):
                            raise StorageError(f"ledger line {line_number} is not an object")
                        self._validate_entry_fast(value, previous_sequence, previous_entry_identity, line_number)
                        prev_for_last = previous_entry_identity
                        previous_sequence = int(value["sequence"])
                        previous_entry_identity = str(value["entry_identity"])
                        last_entry = value
                        count += 1
                        cur_last_offset = cur_offset
                        cur_last_length = line_len
                        if not trailing_partial:
                            new_rows.append(
                                (
                                    previous_sequence,
                                    cur_offset,
                                    line_len,
                                    str(value["record_type"]),
                                    _digest_bytes(str(value["record_identity"])),
                                )
                            )
                        cur_offset += line_len

                if trailing_partial and last_entry is not None and not diagnostics:
                    diagnostics.append(
                        LedgerDiagnostic(
                            "TRAILING_NEWLINE_MISSING",
                            "valid final ledger entry is missing its newline",
                            count,
                        )
                    )
                if not diagnostics and new_rows and last_entry is not None:
                    conn.execute("BEGIN")
                    for idx in range(0, len(new_rows), _INDEX_BATCH_SIZE):
                        conn.executemany(
                            "INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?)",
                            new_rows[idx : idx + _INDEX_BATCH_SIZE],
                        )
                    conn.execute(
                        """
                        UPDATE meta
                        SET ledger_size = ?, record_count = ?, prev_entry_id = ?,
                            last_offset = ?, last_length = ?, last_entry_id = ?
                        WHERE id = 1
                        """,
                        (
                            stat.st_size,
                            count,
                            prev_for_last,
                            cur_last_offset,
                            cur_last_length,
                            str(last_entry["entry_identity"]),
                        ),
                    )
                    conn.execute("COMMIT")
                self._verified_token = token
                self._record_count = count
                self._last_entry = last_entry
                self._diagnostics = diagnostics
                self._partial = trailing_partial
                return count, last_entry, diagnostics, trailing_partial
        except StorageError:
            # Anchor or interior corruption: fall back to full byte-0 audit so exact
            # line-level StorageError is raised deterministically.
            return None
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return None

    def _append_entries_to_index_unlocked(
        self,
        new_entries: list[tuple[dict[str, Any], int, int, str | None]],
        *,
        new_ledger_size: int,
    ) -> None:
        if not new_entries:
            return
        try:
            with closing(self._connect_index_unlocked()) as conn:
                self._init_index_schema(conn)
                meta = conn.execute("SELECT record_count, first_offset, first_length, first_entry_id FROM meta WHERE id = 1").fetchone()
                first_entry, first_off, first_len, _ = new_entries[0]
                if meta is None:
                    if int(first_entry["sequence"]) != 1 or first_off != 0:
                        conn.close()
                        self._remove_index_unlocked()
                        return
                    first_offset = 0
                    first_length = first_len
                    first_entry_id = str(first_entry["entry_identity"])
                else:
                    first_offset = int(meta[1])
                    first_length = int(meta[2])
                    first_entry_id = str(meta[3])
                rows = [
                    (
                        int(entry["sequence"]),
                        offset,
                        length,
                        str(entry["record_type"]),
                        _digest_bytes(str(entry["record_identity"])),
                    )
                    for entry, offset, length, _ in new_entries
                ]
                last_entry, last_off, last_len, prev_id = new_entries[-1]
                conn.execute("BEGIN")
                conn.executemany("INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?)", rows)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO meta (
                        id, schema_version, ledger_size, record_count,
                        first_offset, first_length, first_entry_id,
                        prev_entry_id, last_offset, last_length, last_entry_id
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        INDEX_SCHEMA,
                        new_ledger_size,
                        int(last_entry["sequence"]),
                        first_offset,
                        first_length,
                        first_entry_id,
                        prev_id,
                        last_off,
                        last_len,
                        str(last_entry["entry_identity"]),
                    ),
                )
                conn.execute("COMMIT")
        except (sqlite3.Error, OSError):
            self._remove_index_unlocked()

    def _lookup_by_record_identity_unlocked(self, record_identity: str) -> dict[str, Any] | None:
        if self._record_count == 0 or not self.path.exists():
            return None
        if self._last_entry is not None and self._last_entry.get("record_identity") == record_identity:
            return self._last_entry
        if not self._index_path.exists():
            self._verify_unlocked(full=True)
        if self._index_path.exists():
            try:
                with closing(self._connect_index_unlocked()) as conn:
                    rows = conn.execute(
                        "SELECT seq, offset, length FROM entries WHERE record_id = ? ORDER BY seq ASC",
                        (_digest_bytes(record_identity),),
                    ).fetchall()
                for seq, offset, length in rows:
                    candidate = self._read_entry_at_unlocked(int(offset), int(length), line_hint=int(seq))
                    if candidate.get("record_identity") == record_identity:
                        return candidate
                return None
            except (sqlite3.Error, OSError, StorageError):
                self._remove_index_unlocked()
        for existing in self._stream_unlocked():
            if existing.get("record_identity") == record_identity:
                return existing
        return None

    def _verify_unlocked(self, *, full: bool = False) -> tuple[int, dict[str, Any] | None, list[LedgerDiagnostic], bool]:
        if not self.path.exists():
            self._remove_index_unlocked()
            self._verified_token = None
            self._full_audit_token = None
            self._record_count = 0
            self._last_entry = None
            self._diagnostics = []
            self._partial = False
            return 0, None, [], False
        stat = self.path.stat()
        token = (stat.st_size, stat.st_mtime_ns)
        if stat.st_size == 0:
            self._remove_index_unlocked()
            self._verified_token = token
            self._full_audit_token = token
            self._record_count = 0
            self._last_entry = None
            self._diagnostics = []
            self._partial = False
            return 0, None, [], False

        need_index_rebuild = True
        if full:
            if token == self._full_audit_token and (self._record_count == 0 or self._index_path.exists()):
                return (
                    self._record_count,
                    self._last_entry,
                    self._diagnostics,
                    self._partial,
                )
            synced = self._sync_from_index_unlocked(stat, token)
            if synced is not None and not synced[2]:
                need_index_rebuild = False
        else:
            if token == self._verified_token and (self._record_count == 0 or self._index_path.exists()):
                return (
                    self._record_count,
                    self._last_entry,
                    self._diagnostics,
                    self._partial,
                )
            synced = self._sync_from_index_unlocked(stat, token)
            if synced is not None:
                return synced

        count = 0
        previous_sequence = 0
        previous_entry_identity: str | None = None
        prev_for_last: str | None = None
        last_entry: dict[str, Any] | None = None
        diagnostics: list[LedgerDiagnostic] = []
        trailing_partial = False

        first_length = 0
        first_entry_id = ""
        last_offset = 0
        last_length = 0
        cur_offset = 0

        conn: sqlite3.Connection | None = None
        batch: list[tuple[int, int, int, str, bytes]] = []
        if need_index_rebuild:
            self._remove_index_unlocked()
            try:
                conn = self._connect_index_unlocked()
                self._init_index_tables(conn)
                conn.execute("BEGIN")
            except sqlite3.Error:
                if conn is not None:
                    conn.close()
                conn = None

        try:
            with self.path.open("rb") as stream:
                line_number = 0
                for line in stream:
                    line_number += 1
                    line_len = len(line)
                    trailing_partial = not line.endswith(b"\n")
                    stripped = line.rstrip(b"\r\n")
                    if not stripped:
                        if trailing_partial:
                            diagnostics.append(
                                LedgerDiagnostic("TRUNCATED_TAIL", "empty line in partial tail", line_number)
                            )
                            break
                        raise StorageError(f"ledger line {line_number} is empty")
                    try:
                        value = json.loads(stripped.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        if trailing_partial:
                            diagnostics.append(LedgerDiagnostic("TRUNCATED_TAIL", str(exc), line_number))
                            break
                        raise StorageError(f"ledger line {line_number} is corrupt: {exc}") from exc
                    if not isinstance(value, dict):
                        raise StorageError(f"ledger line {line_number} is not an object")
                    self._validate_entry_fast(value, previous_sequence, previous_entry_identity, line_number)
                    prev_for_last = previous_entry_identity
                    previous_sequence = int(value["sequence"])
                    previous_entry_identity = str(value["entry_identity"])
                    last_entry = value
                    count += 1
                    if count == 1:
                        first_length = line_len
                        first_entry_id = previous_entry_identity
                    last_offset = cur_offset
                    last_length = line_len
                    if conn is not None and not trailing_partial:
                        batch.append(
                            (
                                previous_sequence,
                                cur_offset,
                                line_len,
                                str(value["record_type"]),
                                _digest_bytes(str(value["record_identity"])),
                            )
                        )
                        if len(batch) >= _INDEX_BATCH_SIZE:
                            conn.executemany("INSERT INTO entries VALUES (?, ?, ?, ?, ?)", batch)
                            batch.clear()
                    cur_offset += line_len

            if trailing_partial and last_entry is not None and not diagnostics:
                diagnostics.append(
                    LedgerDiagnostic(
                        "TRAILING_NEWLINE_MISSING",
                        "valid final ledger entry is missing its newline",
                        count,
                    )
                )

            if conn is not None:
                if not diagnostics and count > 0 and last_entry is not None:
                    if batch:
                        conn.executemany("INSERT INTO entries VALUES (?, ?, ?, ?, ?)", batch)
                        batch.clear()
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO meta (
                            id, schema_version, ledger_size, record_count,
                            first_offset, first_length, first_entry_id,
                            prev_entry_id, last_offset, last_length, last_entry_id
                        ) VALUES (1, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            INDEX_SCHEMA,
                            stat.st_size,
                            count,
                            first_length,
                            first_entry_id,
                            prev_for_last,
                            last_offset,
                            last_length,
                            str(last_entry["entry_identity"]),
                        ),
                    )
                    self._init_index_indexes(conn)
                    conn.execute("COMMIT")
                    conn.close()
                    conn = None
                else:
                    conn.close()
                    conn = None
                    self._remove_index_unlocked()
        except Exception:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                self._remove_index_unlocked()
            raise

        self._verified_token = token
        self._full_audit_token = token
        self._record_count = count
        self._last_entry = last_entry
        self._diagnostics = diagnostics
        self._partial = trailing_partial
        return count, last_entry, diagnostics, trailing_partial

    @staticmethod
    def _validate_entry(value: dict[str, Any], previous: dict[str, Any] | None, line: int) -> None:
        prev_seq = int(previous["sequence"]) if previous else 0
        prev_id = str(previous["entry_identity"]) if previous else None
        FabricLedger._validate_entry_fast(value, prev_seq, prev_id, line)

    @staticmethod
    def _validate_entry_fast(
        value: dict[str, Any],
        previous_sequence: int,
        previous_identity: str | None,
        line: int,
    ) -> None:
        if value.get("schema_version") != LEDGER_SCHEMA:
            raise StorageError(f"ledger line {line} uses an unsupported schema version")
        required = {
            "schema_version",
            "sequence",
            "previous_identity",
            "record_type",
            "record",
            "record_identity",
            "entry_identity",
        }
        if set(value) != required:
            raise StorageError(f"ledger line {line} has an unexpected field set")
        sequence = value.get("sequence")
        expected_seq = previous_sequence + 1 if previous_sequence > 0 else 1
        if not isinstance(sequence, int) or sequence != expected_seq:
            raise StorageError(f"ledger sequence is invalid at line {line}")
        if value.get("previous_identity") != previous_identity:
            raise StorageError(f"ledger hash linkage is invalid at line {line}")
        record = value.get("record")
        if not isinstance(record, dict) or value.get("record_identity") != sha256_identity(record):
            raise StorageError(f"ledger record identity is invalid at line {line}")
        material = {key: item for key, item in value.items() if key != "entry_identity"}
        if value.get("entry_identity") != sha256_identity(material):
            raise StorageError(f"ledger entry identity is invalid at line {line}")

    def _stream_unlocked(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("rb") as stream:
            for line in stream:
                stripped = line.rstrip(b"\r\n")
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped.decode("utf-8"))
                except Exception:
                    continue
                if isinstance(value, dict):
                    yield value

    def verify(self) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            count, _, diagnostics, _ = self._verify_unlocked(full=True)
        return {
            "schema_version": LEDGER_SCHEMA,
            "record_count": count,
            "diagnostics": [diagnostic.__dict__ for diagnostic in diagnostics],
            "outcome": "UNKNOWN" if diagnostics else "PASS",
        }

    def recover(self, *, repair_truncated_tail: bool = False) -> dict[str, Any]:
        with _exclusive_lock(self.path):
            count, _, diagnostics, partial = self._verify_unlocked(full=True)
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
                self._remove_index_unlocked()
                self._verified_token = None
                self._full_audit_token = None
                count, _, diagnostics, _ = self._verify_unlocked(full=True)
        return {
            "record_count": count,
            "diagnostics": [diagnostic.__dict__ for diagnostic in diagnostics],
            "repaired": repaired,
            "outcome": "PASS" if not diagnostics or repaired else "UNKNOWN",
        }

    def append(self, record_type: str, record: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(record_type, str) or not record_type:
            raise StorageError("record_type must be a non-empty string")
        with _exclusive_lock(self.path):
            count, last_entry, diagnostics, _ = self._verify_unlocked(full=False)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            record_identity = sha256_identity(record)
            existing = self._lookup_by_record_identity_unlocked(record_identity)
            if existing is not None:
                if existing.get("record_type") != record_type or existing.get("record") != record:
                    raise StorageError("conflicting duplicate record identity")
                return existing
            previous_identity = last_entry["entry_identity"] if last_entry else None
            entry: dict[str, Any] = {
                "schema_version": LEDGER_SCHEMA,
                "sequence": count + 1,
                "previous_identity": previous_identity,
                "record_type": record_type,
                "record": record,
                "record_identity": record_identity,
            }
            entry["entry_identity"] = sha256_identity(entry)
            raw_line = canonical_json_bytes(entry) + b"\n"
            offset = self.path.stat().st_size if self.path.exists() else 0
            prev_token = self._verified_token
            had_full_audit = prev_token is not None and self._full_audit_token == prev_token
            with self.path.open("ab") as stream:
                stream.write(raw_line)
                stream.flush()
                os.fsync(stream.fileno())
            stat = self.path.stat()
            new_token = (stat.st_size, stat.st_mtime_ns)
            self._append_entries_to_index_unlocked(
                [(entry, offset, len(raw_line), previous_identity)],
                new_ledger_size=stat.st_size,
            )
            self._verified_token = new_token
            if had_full_audit or count == 0:
                self._full_audit_token = new_token
            self._record_count = count + 1
            self._last_entry = entry
            self._diagnostics = []
            self._partial = False
            return entry

    def append_if(
        self,
        record_type: str,
        record: dict[str, Any],
        predicate: Callable[[list[dict[str, Any]]], None],
    ) -> dict[str, Any]:
        """Append one record while checking a state predicate under the lock.

        Lifecycle authorization is intentionally a read/decision/write
        operation. Keeping the predicate in the ledger critical section
        prevents two controller processes from consuming the same one-time
        authorization.
        """
        if not isinstance(record_type, str) or not record_type:
            raise StorageError("record_type must be a non-empty string")
        with _exclusive_lock(self.path):
            count, last_entry, diagnostics, _ = self._verify_unlocked(full=False)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            records = list(self._stream_unlocked())
            predicate(records)
            record_identity = sha256_identity(record)
            for existing in records:
                if existing.get("record_identity") == record_identity:
                    if existing.get("record_type") != record_type or existing.get("record") != record:
                        raise StorageError("conflicting duplicate record identity")
                    return existing
            previous_identity = last_entry["entry_identity"] if last_entry else None
            entry: dict[str, Any] = {
                "schema_version": LEDGER_SCHEMA,
                "sequence": count + 1,
                "previous_identity": previous_identity,
                "record_type": record_type,
                "record": record,
                "record_identity": record_identity,
            }
            entry["entry_identity"] = sha256_identity(entry)
            raw_line = canonical_json_bytes(entry) + b"\n"
            offset = self.path.stat().st_size if self.path.exists() else 0
            prev_token = self._verified_token
            had_full_audit = prev_token is not None and self._full_audit_token == prev_token
            with self.path.open("ab") as stream:
                stream.write(raw_line)
                stream.flush()
                os.fsync(stream.fileno())
            stat = self.path.stat()
            new_token = (stat.st_size, stat.st_mtime_ns)
            self._append_entries_to_index_unlocked(
                [(entry, offset, len(raw_line), previous_identity)],
                new_ledger_size=stat.st_size,
            )
            self._verified_token = new_token
            if had_full_audit or count == 0:
                self._full_audit_token = new_token
            self._record_count = count + 1
            self._last_entry = entry
            self._diagnostics = []
            self._partial = False
            return entry

    def append_many_if(
        self,
        records_to_append: list[tuple[str, dict[str, Any]]],
        predicate: Callable[[list[dict[str, Any]]], None],
    ) -> list[dict[str, Any]]:
        """Append a bounded batch after one locked state check.

        This is used when an authorization consumption and its enrollment
        request must become one durable controller decision. The batch is
        small and all records are prepared before any bytes are written.
        """
        if not records_to_append or len(records_to_append) > 8:
            raise StorageError("ledger append batch is outside the bounded range")
        if any(not isinstance(record_type, str) or not record_type for record_type, _ in records_to_append):
            raise StorageError("record_type must be a non-empty string")
        with _exclusive_lock(self.path):
            count, last_entry, diagnostics, _ = self._verify_unlocked(full=False)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            records = list(self._stream_unlocked())
            predicate(records)
            entries: list[dict[str, Any]] = []
            previous = last_entry
            for record_type, record in records_to_append:
                record_identity = sha256_identity(record)
                for existing in records + entries:
                    if existing.get("record_identity") == record_identity:
                        if existing.get("record_type") != record_type or existing.get("record") != record:
                            raise StorageError("conflicting duplicate record identity")
                        entries.append(existing)
                        break
                else:
                    entry = {
                        "schema_version": LEDGER_SCHEMA,
                        "sequence": count + len(entries) + 1,
                        "previous_identity": previous["entry_identity"] if previous else None,
                        "record_type": record_type,
                        "record": record,
                        "record_identity": record_identity,
                    }
                    entry["entry_identity"] = sha256_identity(entry)
                    entries.append(entry)
                    previous = entry
            new_entries = [entry for entry in entries if entry not in records]
            if new_entries:
                offset = self.path.stat().st_size if self.path.exists() else 0
                prev_token = self._verified_token
                had_full_audit = prev_token is not None and self._full_audit_token == prev_token
                indexed_batch: list[tuple[dict[str, Any], int, int, str | None]] = []
                with self.path.open("ab") as stream:
                    for entry in new_entries:
                        raw_line = canonical_json_bytes(entry) + b"\n"
                        stream.write(raw_line)
                        indexed_batch.append(
                            (entry, offset, len(raw_line), entry.get("previous_identity"))
                        )
                        offset += len(raw_line)
                    stream.flush()
                    os.fsync(stream.fileno())
                stat = self.path.stat()
                new_token = (stat.st_size, stat.st_mtime_ns)
                self._append_entries_to_index_unlocked(
                    indexed_batch,
                    new_ledger_size=stat.st_size,
                )
                self._verified_token = new_token
                if had_full_audit or count == 0:
                    self._full_audit_token = new_token
                self._record_count = count + len(new_entries)
                self._last_entry = new_entries[-1]
                self._diagnostics = []
                self._partial = False
            return entries

    def records(self, *, record_type: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or limit < 0 or limit > 100000:
            raise StorageError("ledger read limit is outside the bounded range")
        if limit == 0:
            return []
        with _exclusive_lock(self.path):
            count, _, diagnostics, _ = self._verify_unlocked(full=False)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            if count == 0:
                return []
            if self._index_path.exists():
                try:
                    with closing(self._connect_index_unlocked()) as conn:
                        if record_type is None:
                            rows = conn.execute(
                                "SELECT seq, offset, length FROM entries ORDER BY seq DESC LIMIT ?",
                                (limit,),
                            ).fetchall()
                        else:
                            rows = conn.execute(
                                "SELECT seq, offset, length FROM entries WHERE record_type = ? ORDER BY seq DESC LIMIT ?",
                                (record_type, limit),
                            ).fetchall()
                    rows.reverse()
                    return [
                        self._read_entry_at_unlocked(int(offset), int(length), line_hint=int(seq))
                        for seq, offset, length in rows
                    ]
                except (sqlite3.Error, OSError, StorageError):
                    self._remove_index_unlocked()
            window: collections.deque[dict[str, Any]] = collections.deque(maxlen=limit)
            for entry in self._stream_unlocked():
                if record_type is None or entry.get("record_type") == record_type:
                    window.append(entry)
            return list(window)

    def iter_records(self, *, record_type: str | None = None) -> Iterator[dict[str, Any]]:
        """Stream the validated ledger without retaining its history.

        The file lock is held for the lifetime of the iterator so callers can
        safely derive bounded state from a stable, fully verified ledger. Use
        ``all_records`` only when the caller explicitly needs a materialized
        historical result.
        """

        with _exclusive_lock(self.path):
            _, _, diagnostics, _ = self._verify_unlocked(full=True)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            for entry in self._stream_unlocked():
                if record_type is None or entry.get("record_type") == record_type:
                    yield entry

    def all_records(self, *, record_type: str | None = None) -> list[dict[str, Any]]:
        """Read the full authoritative ledger for deterministic derived-state rebuilds."""

        with _exclusive_lock(self.path):
            _, _, diagnostics, _ = self._verify_unlocked(full=True)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            return [
                entry
                for entry in self._stream_unlocked()
                if record_type is None or entry.get("record_type") == record_type
            ]

    def compact(
        self,
        *,
        keep: Callable[[dict[str, Any]], bool],
        reason: str,
        max_kept: int = 10000,
    ) -> dict[str, Any]:
        """Drop superseded entries and reseal the hash chain.

        ``keep`` decides retention per validated entry while streaming. Kept
        entries are rewritten with contiguous sequences and recomputed
        ``previous_identity``/``entry_identity`` linkage; their record bytes
        (and therefore ``record_identity`` values) are unchanged. A compaction
        receipt binding the pre-compact head identity, the pre/post counts,
        and the operator reason is appended as the final record.

        Only entries whose entry identity is never referenced by another
        record may be dropped; the caller selects a predicate with that
        property (for example superseded rendezvous heartbeats). ``max_kept``
        fails the compaction closed instead of buffering an unbounded kept
        set in RAM.
        """

        if not callable(keep):
            raise StorageError("ledger compaction requires a keep predicate")
        if not isinstance(reason, str) or not reason or len(reason) > 512 or "\x00" in reason:
            raise StorageError("ledger compaction reason must be bounded non-empty text")
        if not isinstance(max_kept, int) or not 1 <= max_kept <= 100000:
            raise StorageError("ledger compaction kept bound is outside the bounded range")
        from datetime import datetime, timezone

        with _exclusive_lock(self.path):
            count, last_entry, diagnostics, _ = self._verify_unlocked(full=True)
            if diagnostics:
                raise StorageError("ledger has an unrepaired truncated tail")
            kept: list[dict[str, Any]] = []
            for entry in self._stream_unlocked():
                if keep(entry):
                    kept.append(entry)
                    if len(kept) > max_kept:
                        raise StorageError("ledger compaction kept set exceeds its bound")
            dropped = count - len(kept)
            resealed: list[dict[str, Any]] = []
            previous_identity: str | None = None
            for index, entry in enumerate(kept, start=1):
                resealed_entry: dict[str, Any] = {
                    "schema_version": LEDGER_SCHEMA,
                    "sequence": index,
                    "previous_identity": previous_identity,
                    "record_type": entry.get("record_type"),
                    "record": entry.get("record"),
                    "record_identity": entry.get("record_identity"),
                }
                resealed_entry["entry_identity"] = sha256_identity(resealed_entry)
                resealed.append(resealed_entry)
                previous_identity = resealed_entry["entry_identity"]
            receipt = {
                "schema_version": COMPACTION_SCHEMA,
                "reason": reason,
                "pre_compact_head": last_entry["entry_identity"] if last_entry else None,
                "pre_compact_count": count,
                "kept_count": len(resealed),
                "dropped_count": dropped,
                "compacted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "claim_boundary": "compaction receipt; dropped entries were superseded and unreferenced",
            }
            receipt_identity = sha256_identity(receipt)
            receipt_entry: dict[str, Any] = {
                "schema_version": LEDGER_SCHEMA,
                "sequence": len(resealed) + 1,
                "previous_identity": previous_identity,
                "record_type": "ledger.compaction",
                "record": receipt,
                "record_identity": receipt_identity,
            }
            receipt_entry["entry_identity"] = sha256_identity(receipt_entry)
            resealed.append(receipt_entry)
            staged = self.path.with_name(self.path.name + f".compact.{os.getpid()}.tmp")
            indexed_batch: list[tuple[dict[str, Any], int, int, str | None]] = []
            offset = 0
            with staged.open("wb") as stream:
                for item in resealed:
                    raw_line = canonical_json_bytes(item) + b"\n"
                    stream.write(raw_line)
                    indexed_batch.append(
                        (item, offset, len(raw_line), item.get("previous_identity"))
                    )
                    offset += len(raw_line)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(staged, self.path)
            stat = self.path.stat()
            self._remove_index_unlocked()
            self._append_entries_to_index_unlocked(
                indexed_batch,
                new_ledger_size=stat.st_size,
            )
            token = (stat.st_size, stat.st_mtime_ns)
            self._verified_token = token
            self._full_audit_token = token
            self._record_count = len(resealed)
            self._last_entry = resealed[-1]
            self._diagnostics = []
            self._partial = False
            return {
                "schema_version": COMPACTION_SCHEMA,
                "reason": reason,
                "pre_compact_head": receipt["pre_compact_head"],
                "pre_compact_count": count,
                "kept_count": len(resealed) - 1,
                "dropped_count": dropped,
                "post_compact_count": len(resealed),
                "compaction_identity": receipt_entry["entry_identity"],
                "claim_boundary": receipt["claim_boundary"],
            }
