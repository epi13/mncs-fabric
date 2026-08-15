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
        self.assertLess(parse_fabric_version("0.2.0a19"), parse_fabric_version("0.2.0a21"))
        self.assertGreaterEqual(parse_fabric_version("0.2.0a21"), (0, 2, 0, 21))

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
