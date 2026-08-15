from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mncs_fabric.supervisor import (
    classify_worker_version,
    inspect_supervisor,
    parse_fabric_version,
    restart_supervisor,
    validate_supervisor,
    write_upgrade_request,
)


class SupervisorTests(unittest.TestCase):
    def test_version_compatibility_policy(self) -> None:
        self.assertEqual(classify_worker_version("0.2.0a21"), "current")
        self.assertEqual(classify_worker_version("0.2.0a22"), "current")
        self.assertEqual(classify_worker_version("0.2.0a19"), "upgradeable")
        self.assertEqual(classify_worker_version("0.2.0a10"), "upgradeable")
        self.assertEqual(classify_worker_version("0.2.0a6"), "upgradeable")
        self.assertEqual(classify_worker_version("0.1.0"), "bootstrap-required")
        self.assertEqual(classify_worker_version(None), "unsupported")

    def test_parse_version_orders_prereleases(self) -> None:
        left = parse_fabric_version("0.2.0a19")
        right = parse_fabric_version("0.2.0a21")
        self.assertIsNotNone(left)
        self.assertIsNotNone(right)
        self.assertLess(left, right)
        self.assertIsNone(parse_fabric_version("not-a-version"))
        self.assertIsNone(parse_fabric_version("0.2.0a"))
        self.assertIsNone(parse_fabric_version("1.2.3.4.5"))

    def test_inspect_supervisor_is_identity_bound(self) -> None:
        observed = inspect_supervisor(worker_id="local-test")
        checked = validate_supervisor(observed)
        self.assertEqual(checked["worker_identity"], "local-test")
        self.assertIn(checked["kind"], {"systemd-user", "windows-scheduled-task", "windows-service", "process", "absent"})

    def test_missing_supervisor_restart_is_typed(self) -> None:
        result = restart_supervisor({"kind": "process", "unit": None})
        self.assertEqual(result["disposition"], "SKIPPED")
        self.assertEqual(result["failure_class"], "UNSUPPORTED_ACTION")

    def test_upgrade_request_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_upgrade_request(source="/tmp/src", version="0.2.0a21", stage_dir=Path(directory))
            self.assertTrue(path.is_file())
            text = path.read_text(encoding="utf-8")
            self.assertIn("0.2.0a21", text)
            self.assertIn("/tmp/src", text)

    def test_digest_named_wheel_is_copied_to_pep427_name(self) -> None:
        from mncs_fabric.package_artifact import describe_package_artifact
        from mncs_fabric.supervisor import installable_upgrade_source

        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "mncs_fabric-0.2.0a30-py3-none-any.whl"
            original.write_bytes(b"wheel-bytes")
            described = describe_package_artifact(original, version="0.2.0a30")
            digest_name = described["digest"].split(":", 1)[1] + ".whl"
            staged = Path(directory) / digest_name
            original.rename(staged)
            (Path(directory) / "artifact.json").write_text(
                __import__("json").dumps(described, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            installable = installable_upgrade_source(str(staged))
            self.assertEqual(installable.name, "mncs_fabric-0.2.0a30-py3-none-any.whl")
            self.assertTrue(installable.is_file())
            self.assertEqual(installable.read_bytes(), b"wheel-bytes")
            self.assertTrue(staged.is_file())

    def test_digest_named_sdist_is_already_installable(self) -> None:
        from mncs_fabric.supervisor import installable_upgrade_source

        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / ("a" * 64 + ".tar.gz")
            staged.write_bytes(b"sdist-bytes")
            self.assertEqual(installable_upgrade_source(str(staged)), staged)

    def test_resolve_upgrade_source_prefers_existing_path(self) -> None:
        from mncs_fabric.supervisor import resolve_upgrade_source

        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / "mncs-fabric-0.2.0a23.tar.gz"
            staged.write_text("sdist", encoding="utf-8")
            self.assertEqual(resolve_upgrade_source("0.2.0a23", stage_dir=Path(directory)), staged)
            self.assertIsNone(resolve_upgrade_source("missing", stage_dir=Path(directory)))

    def test_windows_scheduled_task_restart_uses_launcher_not_schtasks(self) -> None:
        from mncs_fabric.supervisor import restart_supervisor

        result = restart_supervisor({"kind": "windows-scheduled-task", "unit": "MNCS-Fabric-Worker", "worker_identity": "win-test"})
        self.assertIn(result["disposition"], {"PASS", "FAIL", "SKIPPED"})
        self.assertNotIn("schtasks /Run", str(result))
