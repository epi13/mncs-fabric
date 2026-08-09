from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.linux_worker_preflight import _alias_ssh_args, _diagnostic_record, _operator_values, _resolve_alias, _ssh_args, build_parser
from mncs_fabric.evidence import validate_physical_evidence
from mncs_fabric.node import capability_names


class RaspberryPiPortabilityTests(unittest.TestCase):
    def test_arm_architecture_is_a_generic_capability(self) -> None:
        names = capability_names({"os": "linux", "architecture": "armv7l", "python_version": "3.11.2", "tools": {}})
        self.assertIn("os:linux", names)
        self.assertIn("arch:armv7l", names)
        self.assertNotIn("raspberry-pi", names)

    def test_preflight_uses_strict_public_key_only_ssh(self) -> None:
        args = _ssh_args("mncs-pi.local", "pi", Path("/tmp/pi-key"))
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("IdentitiesOnly=yes", args)
        self.assertIn("PasswordAuthentication=no", args)
        self.assertIn("KbdInteractiveAuthentication=no", args)
        self.assertNotIn("-L", args)

    def test_alias_mode_preserves_agent_configuration_without_password_fallback(self) -> None:
        args = _alias_ssh_args("mncs-pi", None)
        self.assertIn("IdentitiesOnly=no", args)
        self.assertIn("PreferredAuthentications=publickey", args)
        self.assertIn("PasswordAuthentication=no", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertNotIn("-i", args)

    def test_alias_resolution_keeps_only_bounded_non_secret_facts(self) -> None:
        output = """hostname 192.0.2.40\nuser pi\nport 22\nidentityfile /home/pi/.ssh/id_ed25519\nproxycommand none\npubkeyauthentication true\n"""
        completed = __import__("subprocess").CompletedProcess(["ssh", "-G", "mncs-pi"], 0, output, "")
        with patch("scripts.linux_worker_preflight.subprocess.run", return_value=completed):
            resolved, result = _resolve_alias("mncs-pi")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(resolved["hostname"], "192.0.2.40")
        self.assertEqual(resolved["user"], "pi")
        self.assertTrue(resolved["public_key_authentication"])
        self.assertNotIn("identityfile", resolved)

    def test_missing_alias_is_unknown_and_not_discovered(self) -> None:
        completed = __import__("subprocess").CompletedProcess(["ssh", "-G", "missing-pi"], 255, "", "bad alias")
        with patch("scripts.linux_worker_preflight.subprocess.run", return_value=completed):
            resolved, result = _resolve_alias("missing-pi")
        self.assertIsNone(resolved)
        self.assertEqual(result.returncode, 255)

    def test_alias_and_explicit_endpoint_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "pi.json"
            config.write_text(json.dumps({
                "ssh_alias": "mncs-pi",
                "ssh_host": "192.0.2.40",
                "expected_hostname": "raspberrypi",
                "controller_id": "fabric-controller-01",
            }), encoding="utf-8")
            args = build_parser().parse_args(["--config", str(config), "--output", str(Path(directory) / "evidence.json")])
            with self.assertRaisesRegex(SystemExit, "cannot be combined"):
                _operator_values(args)

    def test_alias_diagnostic_without_effective_host_is_valid_bootstrap_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "pi.json"
            config.write_text(json.dumps({
                "ssh_alias": "mncs-pi",
                "expected_hostname": "raspberrypi",
                "controller_id": "fabric-controller-01",
            }), encoding="utf-8")
            args = _operator_values(build_parser().parse_args(["--config", str(config), "--output", str(Path(directory) / "evidence.json")]))
            evidence = _diagnostic_record(args, outcome="UNKNOWN", blocker="SSH_ALIAS_CONFIGURATION_UNAVAILABLE")
            report = validate_physical_evidence(evidence)
            self.assertEqual(report["outcome"], "PASS")

    def test_operator_config_is_explicit_and_does_not_discover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "pi.json"
            config.write_text(json.dumps({
                "ssh_host": "mncs-pi.local",
                "ssh_user": "pi",
                "ssh_key": "/tmp/pi-key",
                "worker_host": "mncs-pi.local",
                "expected_hostname": "raspberrypi",
                "worker_id": "raspberry-pi",
                "controller_id": "fabric-controller-01",
            }), encoding="utf-8")
            args = build_parser().parse_args(["--config", str(config), "--output", str(Path(directory) / "evidence.json")])
            resolved = _operator_values(args)
            self.assertEqual(resolved.ssh_host, "mncs-pi.local")
            self.assertEqual(resolved.ssh_user, "pi")
            self.assertEqual(resolved.worker_host, "mncs-pi.local")
            self.assertEqual(resolved.config_source, str(config))

    def test_unknown_preflight_evidence_is_valid_but_not_execution_evidence(self) -> None:
        evidence = json.loads((Path(__file__).parents[1] / "development-evidence/raspberry-pi-preflight.json").read_text(encoding="utf-8"))
        report = validate_physical_evidence(evidence)
        self.assertEqual(report["outcome"], "PASS")
        self.assertFalse(evidence["direct_fabric_tls"])
        self.assertFalse(evidence["fabric_execution_attempted"])


if __name__ == "__main__":
    unittest.main()
