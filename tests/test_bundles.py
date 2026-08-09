from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from mncs_fabric.bundles import bind_receipt_to_bundle, verify_bundle_archive
from mncs_fabric.jcs import canonical_jcs_bytes


def _manifest(path: str = "harness/run.py", content: bytes = b"print('ok')\n") -> tuple[dict[str, object], dict[str, bytes]]:
    entry = {"path": path, "identity": hashlib.sha256(content).hexdigest(), "size_bytes": len(content), "role": "harness", "mode": "0644"}
    manifest: dict[str, object] = {
        "schema_version": "0.1-experimental", "record_type": "mncs-execution-bundle", "bundle_id": "bundle.test-v1", "bundle_identity": "0" * 64,
        "bundle_format": "mncs-execution-bundle-zip-0.1", "entries": [entry], "entrypoints": [{"name": "harness", "path": path}], "runtime_requirements": [], "policy_references": [],
        "harness_identity": hashlib.sha256(canonical_jcs_bytes({"role": "harness", "entries": [{"path": path, "identity": entry["identity"], "mode": "0644"}]})).hexdigest(), "input_snapshot_identity": None, "policy_identity": None,
        "limits": {"max_file_count": 32, "max_file_bytes": 65536, "max_total_bytes": 262144, "max_path_bytes": 512, "max_expansion_ratio": 100}, "extensions": {},
    }
    material = {key: value for key, value in manifest.items() if key != "bundle_identity"}
    manifest["bundle_identity"] = hashlib.sha256(canonical_jcs_bytes(material)).hexdigest()
    return manifest, {path: content}


def _write_bundle(path: Path, manifest: dict[str, object], content: dict[str, bytes], *, extra: list[tuple[str, bytes, int]] | None = None) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        info = zipfile.ZipInfo("manifest.json", (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, canonical_jcs_bytes(manifest))
        for name, data in content.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
        for name, data, mode in extra or []:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, data)


class BundleTests(unittest.TestCase):
    def test_deterministic_identity_and_archive_binding(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, content = _manifest()
            first = root / "first.zip"
            second = root / "second.zip"
            _write_bundle(first, manifest, content)
            _write_bundle(second, manifest, content)
            one = verify_bundle_archive(first)
            two = verify_bundle_archive(second)
            self.assertEqual(one.category, "PASS")
            self.assertEqual(one.bundle_identity, two.bundle_identity)
            self.assertEqual(one.archive_identity, two.archive_identity)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_receipt_binding_keeps_logical_and_transport_identity_distinct(self) -> None:
        with TemporaryDirectory() as directory:
            manifest, content = _manifest()
            archive = Path(directory) / "bundle.zip"
            _write_bundle(archive, manifest, content)
            report = verify_bundle_archive(archive)
            receipt = {"bundle": {"test_bundle_identity": manifest["bundle_identity"], "harness_identity": manifest["harness_identity"], "input_snapshot_identity": None}, "policy": {"execution_policy_identity": None}}
            self.assertEqual(bind_receipt_to_bundle(receipt, report).category, "PASS")
            self.assertTrue(report.bundle_identity and not report.bundle_identity.startswith("sha256:"))
            self.assertTrue(report.archive_identity and report.archive_identity.startswith("sha256:"))
            receipt["bundle"]["test_bundle_identity"] = "f" * 64  # type: ignore[index]
            self.assertEqual(bind_receipt_to_bundle(receipt, report).category, "FAIL")

    def test_adversarial_paths_collision_special_and_substitution(self) -> None:
        cases = ["../escape", "/absolute", "C:/drive", "C:\\drive", "\\\\server\\share", "a//b", "a/../b", "e\u0301.txt"]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for path in cases:
                manifest, content = _manifest(path)
                archive = root / (str(cases.index(path)) + ".zip")
                _write_bundle(archive, manifest, content)
                self.assertEqual(verify_bundle_archive(archive).category, "FAIL", path)
            manifest, content = _manifest()
            collision = root / "collision.zip"
            _write_bundle(collision, manifest, content, extra=[("HARNESS/run.py", b"x", (stat.S_IFREG | 0o644))])
            self.assertEqual(verify_bundle_archive(collision).category, "FAIL")
            special = root / "special.zip"
            _write_bundle(special, manifest, content, extra=[("device", b"x", stat.S_IFCHR | 0o644)])
            self.assertEqual(verify_bundle_archive(special).category, "FAIL")
            self.assertEqual(verify_bundle_archive(collision, expected_bundle_identity="0" * 64).category, "FAIL")

    def test_unknown_version_fails_closed_without_acceptance(self) -> None:
        with TemporaryDirectory() as directory:
            manifest, content = _manifest()
            manifest["schema_version"] = "0.2-experimental"
            archive = Path(directory) / "future.zip"
            _write_bundle(archive, manifest, content)
            result = verify_bundle_archive(archive)
            self.assertEqual(result.category, "UNKNOWN")
            self.assertFalse(result.valid)
