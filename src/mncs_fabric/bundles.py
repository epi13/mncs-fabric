"""Self-contained compatibility boundary for MNCS EA-NEXT-002 bundles.

This module verifies the current ``mncs-execution-bundle-0.1-experimental``
shape without extracting or executing an archive.  It deliberately does not
turn package integrity into execution assurance, correctness, conformance,
sandboxing, custody, or independence.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import attach_identity, sha256_identity
from .jcs import canonical_jcs_bytes

SCHEMA_VERSION = "0.1-experimental"
RECORD_TYPE = "mncs-execution-bundle"
BUNDLE_FORMAT = "mncs-execution-bundle-zip-0.1"
MANIFEST_NAME = "manifest.json"
MAX_FILE_COUNT = 2_000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_EXPANSION_RATIO = 100
ROLES = {"test", "harness", "expected", "manifest", "fixture", "input", "runtime-requirement", "policy-reference", "support"}
MODES = {"0644", "0755"}


@dataclass(frozen=True)
class BundleIssue:
    code: str
    message: str
    path: str = ""


@dataclass
class BundleReport:
    target: str
    valid: bool = True
    supported: bool = True
    bundle_id: str | None = None
    bundle_identity: str | None = None
    archive_identity: str | None = None
    manifest: dict[str, Any] | None = None
    issues: list[BundleIssue] = field(default_factory=list)

    @property
    def category(self) -> str:
        if not self.supported:
            return "UNKNOWN"
        return "PASS" if self.valid else "FAIL"

    def invalidate(self, code: str, message: str, path: str = "") -> None:
        self.valid = False
        self.issues.append(BundleIssue(code, message, path))

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "valid": self.valid,
            "supported": self.supported,
            "category": self.category,
            "bundle_id": self.bundle_id,
            "bundle_identity": self.bundle_identity,
            "archive_identity": self.archive_identity,
            "manifest": self.manifest,
            "issues": [issue.__dict__ for issue in self.issues],
        }


def _raw_hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _archive_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def normalize_bundle_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("bundle paths must be non-empty strings without NUL")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("bundle paths must use NFC Unicode normalization")
    if "\\" in value or value.startswith("/") or value.startswith("//"):
        raise ValueError("bundle paths must use safe relative POSIX syntax")
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise ValueError("bundle path exceeds the maximum UTF-8 byte length")
    if len(value) >= 2 and value[1] == ":" and value[0].isalpha():
        raise ValueError("Windows drive-letter paths are forbidden")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("bundle paths cannot contain empty, '.', or '..' components")
    if value == MANIFEST_NAME:
        raise ValueError("manifest.json is reserved")
    return value


def _path_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    def reject(value: str) -> None:
        raise ValueError("non-finite JSON number " + value)

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key: " + key)
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
    if not isinstance(value, dict):
        raise ValueError("manifest must be an object")
    return value


def _entry_identity(entries: list[dict[str, Any]], role: str) -> str | None:
    selected = [{"path": entry["path"], "identity": entry["identity"], "mode": entry["mode"]} for entry in entries if entry["role"] == role]
    return hashlib.sha256(canonical_jcs_bytes({"role": role, "entries": selected})).hexdigest() if selected else None


def _reference_identity(references: list[dict[str, str]]) -> str | None:
    return hashlib.sha256(canonical_jcs_bytes({"references": references})).hexdigest() if references else None


def _schema_check(manifest: dict[str, Any], report: BundleReport) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        report.supported = False
        report.invalidate("UNSUPPORTED-SCHEMA", "unsupported execution-bundle schema version", "$/schema_version")
        return
    required = {"schema_version", "record_type", "bundle_id", "bundle_identity", "bundle_format", "entries", "entrypoints", "runtime_requirements", "policy_references", "harness_identity", "input_snapshot_identity", "policy_identity", "limits", "extensions"}
    if set(manifest) != required:
        report.invalidate("SCHEMA", "manifest fields do not match EA-NEXT-002 shape", "$/")
    if manifest.get("record_type") != RECORD_TYPE or manifest.get("bundle_format") != BUNDLE_FORMAT:
        report.invalidate("SCHEMA", "record_type or bundle_format is invalid", "$/")
    for field_name in ("bundle_identity", "harness_identity", "input_snapshot_identity", "policy_identity"):
        value = manifest.get(field_name)
        if value is not None and not _raw_hash(value):
            report.invalidate("SCHEMA", field_name + " must be a raw SHA-256 or null", "$/" + field_name)
    if not isinstance(manifest.get("bundle_id"), str) or not manifest["bundle_id"]:
        report.invalidate("SCHEMA", "bundle_id must be a non-empty string", "$/bundle_id")


def _limits_check(manifest: dict[str, Any], report: BundleReport) -> tuple[int, int, int, int, int] | None:
    limits = manifest.get("limits")
    names = ("max_file_count", "max_file_bytes", "max_total_bytes", "max_path_bytes", "max_expansion_ratio")
    if not isinstance(limits, dict) or set(limits) != set(names) or not all(isinstance(limits.get(name), int) and not isinstance(limits.get(name), bool) and limits[name] > 0 for name in names):
        report.invalidate("LIMITS-INVALID", "bundle limits must contain positive integers", "$/limits")
        return None
    maxima = (MAX_FILE_COUNT, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_PATH_BYTES, MAX_EXPANSION_RATIO)
    values = tuple(limits[name] for name in names)
    for name, value, maximum in zip(names, values, maxima):
        if value > maximum:
            report.invalidate("LIMITS-EXCEED-GLOBAL", name + " exceeds verifier maximum", "$/limits/" + name)
    return values  # type: ignore[return-value]


def _verify_manifest_shape(manifest: dict[str, Any], report: BundleReport, limits: tuple[int, int, int, int, int]) -> dict[str, dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > min(limits[0], MAX_FILE_COUNT):
        report.invalidate("ENTRIES-INVALID", "entries must be a bounded array", "$/entries")
        return {}
    seen: dict[str, str] = {}
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "identity", "size_bytes", "role", "mode"}:
            report.invalidate("ENTRY-INVALID", "entry fields are invalid", "$/entries")
            continue
        path = entry["path"]
        try:
            normalize_bundle_path(path)
        except ValueError as exc:
            report.invalidate("UNSAFE-PATH", str(exc), str(path))
            continue
        key = _path_key(path)
        if key in seen:
            report.invalidate("CASE-COLLISION" if seen[key] != path else "DUPLICATE-PATH", "bundle path collides with " + seen[key], path)
        seen[key] = path
        if not _raw_hash(entry["identity"]):
            report.invalidate("ENTRY-INVALID", "entry identity must be a raw SHA-256", path)
        if not isinstance(entry["size_bytes"], int) or isinstance(entry["size_bytes"], bool) or entry["size_bytes"] < 0 or entry["size_bytes"] > min(limits[1], MAX_FILE_BYTES):
            report.invalidate("FILE-SIZE-LIMIT", "entry size is invalid or exceeds limits", path)
        if entry["role"] not in ROLES or entry["mode"] not in MODES:
            report.invalidate("ENTRY-INVALID", "entry role or mode is invalid", path)
        result[path] = entry
    if [entry.get("path") for entry in entries if isinstance(entry, dict)] != sorted([entry.get("path") for entry in entries if isinstance(entry, dict)], key=lambda value: str(value).encode("utf-8")):
        report.invalidate("ENTRY-ORDER", "entries must be ordered by UTF-8 path", "$/entries")
    total = sum(entry.get("size_bytes", 0) for entry in entries if isinstance(entry, dict) and isinstance(entry.get("size_bytes"), int))
    if total > min(limits[2], MAX_TOTAL_BYTES):
        report.invalidate("TOTAL-SIZE-LIMIT", "entries exceed total size limit", "$/entries")
    return result


def verify_bundle_archive(path: Path, *, expected_bundle_identity: str | None = None, expected_archive_identity: str | None = None) -> BundleReport:
    """Verify an EA-NEXT-002 archive offline, without extraction."""
    report = BundleReport(str(path))
    try:
        archive_path = Path(path)
        size = archive_path.stat().st_size
        report.archive_identity = _archive_hash(archive_path)
        if expected_archive_identity is not None and report.archive_identity != expected_archive_identity:
            report.invalidate("ARCHIVE-IDENTITY-MISMATCH", "archive identity differs from expectation")
        if size > MAX_ARCHIVE_BYTES:
            report.invalidate("ARCHIVE-SIZE-LIMIT", "archive exceeds verifier maximum")
            return report
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_FILE_COUNT + 1:
                report.invalidate("FILE-COUNT-LIMIT", "archive member count exceeds verifier maximum")
                return report
            members: dict[str, bytes] = {}
            seen: dict[str, str] = {}
            total = 0
            for info in infos:
                name = info.filename
                if name == MANIFEST_NAME:
                    normalized = name
                else:
                    try:
                        normalized = normalize_bundle_path(name)
                    except ValueError as exc:
                        report.invalidate("UNSAFE-PATH", str(exc), name)
                        continue
                key = _path_key(normalized)
                if key in seen:
                    report.invalidate("CASE-COLLISION" if seen[key] != normalized else "DUPLICATE-PATH", "duplicate archive member", name)
                    continue
                seen[key] = normalized
                mode = (info.external_attr >> 16) & 0o170000
                if mode != stat.S_IFREG:
                    report.invalidate("SPECIAL-FILE", "archive member is not a regular file", name)
                    continue
                if info.flag_bits & 1:
                    report.invalidate("ENCRYPTED-MEMBER", "encrypted ZIP members are unsupported", name)
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    report.invalidate("FILE-SIZE-LIMIT", "archive member exceeds verifier maximum", name)
                    continue
                if info.compress_size == 0 and info.file_size > 0 or info.compress_size and info.file_size / info.compress_size > MAX_EXPANSION_RATIO:
                    report.invalidate("EXPANSION-LIMIT", "archive member exceeds expansion ratio", name)
                    continue
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    report.invalidate("TOTAL-SIZE-LIMIT", "archive exceeds uncompressed size limit")
                    continue
                with archive.open(info, "r") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != info.file_size or len(data) > MAX_FILE_BYTES:
                    report.invalidate("READ-SIZE-MISMATCH", "archive member size changed while reading", name)
                    continue
                members[normalized] = data
            if not report.valid:
                return report
            if MANIFEST_NAME not in members:
                report.invalidate("MANIFEST-MISSING", "archive does not contain manifest.json")
                return report
            try:
                manifest = _parse_manifest(members[MANIFEST_NAME])
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                report.invalidate("MANIFEST-INVALID", str(exc), MANIFEST_NAME)
                return report
            _schema_check(manifest, report)
            if not report.supported:
                return report
            limits = _limits_check(manifest, report)
            if limits is None:
                return report
            entries = _verify_manifest_shape(manifest, report, limits)
            if canonical_jcs_bytes(manifest) != members[MANIFEST_NAME]:
                report.invalidate("MANIFEST-CANONICAL", "manifest bytes are not canonical JCS", MANIFEST_NAME)
            expected_members = {MANIFEST_NAME, *entries}
            if set(members) != expected_members:
                report.invalidate("MEMBER-SET", "archive members differ from manifest entries")
            for name, entry in entries.items():
                data = members.get(name)
                if data is None or len(data) != entry["size_bytes"] or hashlib.sha256(data).hexdigest() != entry["identity"]:
                    report.invalidate("ENTRY-INTEGRITY", "archive member identity or size differs", name)
                info = next((item for item in infos if item.filename == name), None)
                if info is not None and ((info.external_attr >> 16) & 0o777) != int(entry["mode"], 8):
                    report.invalidate("ENTRY-MODE", "archive member mode differs", name)
            for field_name in ("runtime_requirements", "policy_references", "entrypoints"):
                if not isinstance(manifest.get(field_name), list):
                    report.invalidate("REFERENCE-INVALID", field_name + " must be an array", "$/" + field_name)
            for field_name in ("runtime_requirements", "policy_references"):
                for reference in manifest.get(field_name, []):
                    if not isinstance(reference, dict) or set(reference) != {"path", "identity"} or reference.get("path") not in entries or reference.get("identity") != entries.get(reference.get("path"), {}).get("identity"):
                        report.invalidate("REFERENCE-INVALID", "reference does not bind to an entry", "$/" + field_name)
            for entrypoint in manifest.get("entrypoints", []):
                if not isinstance(entrypoint, dict) or set(entrypoint) != {"name", "path"} or entrypoint.get("path") not in entries:
                    report.invalidate("ENTRYPOINT-INVALID", "entrypoint does not bind to an entry", "$/entrypoints")
            material = {key: value for key, value in manifest.items() if key != "bundle_identity"}
            computed = hashlib.sha256(canonical_jcs_bytes(material)).hexdigest()
            if manifest.get("bundle_identity") != computed:
                report.invalidate("BUNDLE-IDENTITY", "logical bundle identity does not verify", "$/bundle_identity")
            if manifest.get("harness_identity") != _entry_identity(list(entries.values()), "harness") or manifest.get("input_snapshot_identity") != _entry_identity(list(entries.values()), "input") or manifest.get("policy_identity") != _reference_identity(manifest.get("policy_references", [])):
                report.invalidate("REFERENCE-IDENTITY", "derived bundle references do not verify")
            report.manifest = manifest
            report.bundle_id = manifest.get("bundle_id")
            report.bundle_identity = manifest.get("bundle_identity") if _raw_hash(manifest.get("bundle_identity")) else None
            if expected_bundle_identity is not None and report.bundle_identity != expected_bundle_identity:
                report.invalidate("BUNDLE-IDENTITY-MISMATCH", "logical bundle identity differs from expectation")
    except (OSError, zipfile.BadZipFile, ValueError, KeyError) as exc:
        report.invalidate("ARCHIVE-INVALID", str(exc))
    return report


def build_bundle_archive(source_root: Path, archive_path: Path, *, bundle_id: str = "mncs-fabric.bundle.v0.1") -> BundleReport:
    """Build a deterministic EA-NEXT-002 archive from regular source files."""

    source_root = Path(source_root).resolve(strict=True)
    files: list[tuple[str, bytes, str]] = []
    for path in sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix().encode("utf-8")):
        if path.is_symlink() or not path.is_file():
            if path.is_symlink():
                raise ValueError("bundle source cannot contain symbolic links")
            continue
        relative = path.relative_to(source_root).as_posix()
        normalize_bundle_path(relative)
        data = path.read_bytes()
        mode = "0755" if path.stat().st_mode & stat.S_IXUSR else "0644"
        files.append((relative, data, mode))
    if not files:
        raise ValueError("bundle source must contain at least one regular file")
    entries = [{"path": name, "identity": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "role": "harness", "mode": mode} for name, data, mode in files]
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": RECORD_TYPE,
        "bundle_id": bundle_id,
        "bundle_identity": "0" * 64,
        "bundle_format": BUNDLE_FORMAT,
        "entries": entries,
        "entrypoints": [{"name": "harness", "path": files[0][0]}],
        "runtime_requirements": [],
        "policy_references": [],
        "harness_identity": _entry_identity(entries, "harness"),
        "input_snapshot_identity": None,
        "policy_identity": None,
        "limits": {"max_file_count": min(MAX_FILE_COUNT, max(32, len(entries))), "max_file_bytes": MAX_FILE_BYTES, "max_total_bytes": MAX_TOTAL_BYTES, "max_path_bytes": MAX_PATH_BYTES, "max_expansion_ratio": MAX_EXPANSION_RATIO},
        "extensions": {},
    }
    manifest["bundle_identity"] = hashlib.sha256(canonical_jcs_bytes({key: value for key, value in manifest.items() if key != "bundle_identity"})).hexdigest()
    archive_path = Path(archive_path)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        manifest_info = zipfile.ZipInfo(MANIFEST_NAME, (1980, 1, 1, 0, 0, 0))
        manifest_info.create_system = 3
        manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest_info, canonical_jcs_bytes(manifest))
        for name, data, mode in files:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | int(mode, 8)) << 16
            archive.writestr(info, data)
    report = verify_bundle_archive(archive_path, expected_bundle_identity=manifest["bundle_identity"])
    if not report.valid:
        raise ValueError("constructed execution bundle failed self-verification")
    return report


def bind_receipt_to_bundle(receipt: object, bundle: BundleReport) -> BundleReport:
    """Return a binding report; the receipt itself is never rewritten."""
    result = BundleReport("<receipt-binding>", valid=bundle.valid, supported=bundle.supported, bundle_identity=bundle.bundle_identity, archive_identity=bundle.archive_identity, manifest=bundle.manifest)
    if not bundle.valid or bundle.manifest is None:
        result.invalidate("BUNDLE-UNVERIFIED", "receipt cannot bind to an unverified bundle")
        return result
    if not isinstance(receipt, dict):
        result.invalidate("RECEIPT-INVALID", "receipt must be an object")
        return result
    bundle_part = receipt.get("bundle") if isinstance(receipt.get("bundle"), dict) else {}
    policy = receipt.get("policy") if isinstance(receipt.get("policy"), dict) else {}
    manifest = bundle.manifest
    checks = (("test_bundle_identity", manifest.get("bundle_identity")), ("harness_identity", manifest.get("harness_identity")), ("input_snapshot_identity", manifest.get("input_snapshot_identity")))
    for field_name, expected in checks:
        if bundle_part.get(field_name) != expected:
            result.invalidate("RECEIPT-BUNDLE-MISMATCH", field_name + " differs from verified bundle")
    if policy.get("execution_policy_identity") != manifest.get("policy_identity"):
        result.invalidate("RECEIPT-POLICY-MISMATCH", "receipt policy identity differs from verified bundle")
    return result


def build_bundle_binding(*, job_identity: str, candidate_identity: str | None, receipt_identity: str, bundle: BundleReport) -> dict[str, Any]:
    if not bundle.valid or bundle.bundle_identity is None or bundle.archive_identity is None:
        raise ValueError("bundle must be verified before binding")
    value = {"schema_version": "0.1", "record_type": "mncs-fabric.execution-bundle-binding", "job_identity": job_identity, "candidate_identity": candidate_identity, "bundle_identity": bundle.bundle_identity, "archive_identity": bundle.archive_identity, "receipt_identity": receipt_identity, "claim_boundary": "package integrity and identity linkage only; no assurance, correctness, conformance, custody, or independence claim"}
    return attach_identity(value, "binding_identity")
