"""Rebuildable cache for exact-target execution evidence lookups."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from threading import Lock
from typing import Any, Mapping

from .canonical import canonical_json_bytes, sha256_identity
from .errors import ProtocolError
from .store import FabricLedger
from .targets import validate_target_admission, validate_target_execution_evidence


INDEX_SCHEMA = "mncs-fabric.target-evidence-index.v0.1"


class TargetEvidenceIndex:
    """Cache target evidence by request identity; the ledger remains canonical."""

    def __init__(self, ledger: FabricLedger, path: Path) -> None:
        self.ledger = ledger
        self.path = Path(path)
        self._lock = Lock()
        self._entries: dict[str, list[dict[str, Any]]] | None = None
        self._source_signature: dict[str, Any] | None = None

    def _source(self) -> dict[str, Any]:
        if not self.ledger.path.exists():
            return {"size": 0, "mtime_ns": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        stat = self.ledger.path.stat()
        digest = hashlib.sha256()
        with self.ledger.path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "sha256": digest.hexdigest()}

    def _quick_source(self) -> dict[str, int]:
        """Return cheap change detection; the persisted cache still uses a digest."""

        if not self.ledger.path.exists():
            return {"size": 0, "mtime_ns": 0}
        stat = self.ledger.path.stat()
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}

    @staticmethod
    def _normalize_entries(value: object) -> dict[str, list[dict[str, Any]]]:
        if not isinstance(value, dict):
            raise ValueError("target evidence index entries are invalid")
        normalized: dict[str, list[dict[str, Any]]] = {}
        for request_identity, candidates in value.items():
            if not isinstance(request_identity, str) or not isinstance(candidates, list):
                raise ValueError("target evidence index key is invalid")
            checked = [validate_target_execution_evidence(candidate) for candidate in candidates]
            if any(item["execution_request_identity"] != request_identity for item in checked):
                raise ValueError("target evidence index request binding is invalid")
            normalized[request_identity] = checked
        return normalized

    def _load(self, source: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != INDEX_SCHEMA:
            raise ValueError("target evidence index schema is invalid")
        if value.get("source_ledger") != dict(source):
            raise ValueError("target evidence index is stale")
        unsigned = {key: item for key, item in value.items() if key != "index_identity"}
        if sha256_identity(unsigned) != value.get("index_identity"):
            raise ValueError("target evidence index identity is invalid")
        return self._normalize_entries(value.get("entries"))

    def _write(self, source: Mapping[str, Any], entries: Mapping[str, list[dict[str, Any]]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        unsigned = {
            "schema_version": INDEX_SCHEMA,
            "authority": "derived-cache; target-execution.jsonl remains canonical",
            "source_ledger": dict(source),
            "entries": dict(sorted(entries.items())),
        }
        value = {**unsigned, "index_identity": sha256_identity(unsigned)}
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_json_bytes(value))
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            try:
                Path(temporary).unlink()
            except FileNotFoundError:
                pass

    def _rebuild(self, source: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
        entries: dict[str, list[dict[str, Any]]] = {}
        for entry in self.ledger.all_records(record_type="target.execution"):
            evidence = validate_target_execution_evidence(entry["record"])
            entries.setdefault(evidence["execution_request_identity"], []).append(evidence)
        self._write(source, entries)
        return entries

    def _ensure(self) -> dict[str, list[dict[str, Any]]]:
        if (
            self._entries is not None
            and self._source_signature is not None
            and self._quick_source()
            == {
                "size": self._source_signature["size"],
                "mtime_ns": self._source_signature["mtime_ns"],
            }
        ):
            return self._entries
        source = self._source()
        try:
            entries = self._load(source)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            entries = self._rebuild(source)
        self._entries = entries
        self._source_signature = source
        return entries

    def add(self, evidence_value: Mapping[str, Any]) -> None:
        """Refresh the cache after the canonical ledger append has completed."""

        evidence = validate_target_execution_evidence(dict(evidence_value))
        with self._lock:
            entries = self._ensure()
            candidates = entries.setdefault(evidence["execution_request_identity"], [])
            if evidence not in candidates:
                candidates.append(evidence)
            source = self._source()
            self._write(source, entries)
            self._source_signature = source

    def lookup(
        self,
        execution_request_identity: str,
        admission_value: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        admission = validate_target_admission(dict(admission_value))
        binding = admission["request_binding"]
        expected = {
            "target_identity": admission["target_identity"],
            "execution_request_identity": execution_request_identity,
            "authenticated_client_identity": binding["authenticated_client_identity"],
            "client_label": binding["client_label"],
            "consumer_context_identity": binding["consumer_context_identity"],
            "consumer_authorization_identity": binding["consumer_authorization_identity"],
            "worker_identity": result.get("worker_identity"),
            "job_identity": result.get("job_identity"),
            "bundle_identity": result.get("bundle_identity"),
            "record_identity": result.get("record_identity"),
            "receipt_identity": result.get("receipt_identity"),
        }
        with self._lock:
            candidates = list(self._ensure().get(execution_request_identity, ()))
        matching = [
            evidence
            for evidence in candidates
            if all(evidence.get(field) == value for field, value in expected.items())
        ]
        if len(matching) == 1:
            return dict(matching[0])
        if candidates:
            raise ProtocolError(
                "execution request identity conflicts with original target evidence binding"
            )
        return None
