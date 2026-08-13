from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mncs_fabric.cli import _controller_config, build_parser
from mncs_fabric.errors import ValidationError


class ControllerEnvironmentTests(unittest.TestCase):
    def _args(self, root: Path, *extra: str):
        return build_parser().parse_args(
            [
                "controller",
                "--controller-id",
                "controller-env-test",
                "service",
                "run",
                "--state",
                str(root / "lifecycle.jsonl"),
                "--registry",
                str(root / "workers.json"),
                *extra,
            ]
        )

    def test_controller_rendezvous_configuration_loads_from_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = {
                "MNCS_FABRIC_RENDEZVOUS_HOST": "192.0.2.10",
                "MNCS_FABRIC_RENDEZVOUS_PORT": "7444",
                "MNCS_FABRIC_RENDEZVOUS_CA": str(root / "ca.pem"),
                "MNCS_FABRIC_RENDEZVOUS_CERTIFICATE": str(root / "controller.pem"),
                "MNCS_FABRIC_RENDEZVOUS_KEY": str(root / "controller.key"),
                "MNCS_FABRIC_RENDEZVOUS_TRUST_STATE": str(root / "trust.jsonl"),
            }
            with patch.dict(os.environ, environment):
                config = _controller_config(self._args(root))
            self.assertTrue(config.rendezvous_configured)
            self.assertEqual(config.rendezvous_host, "192.0.2.10")
            self.assertEqual(config.rendezvous_port, 7444)
            self.assertEqual(config.rendezvous_ca, root / "ca.pem")

    def test_explicit_rendezvous_arguments_override_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = {
                "MNCS_FABRIC_RENDEZVOUS_HOST": "192.0.2.10",
                "MNCS_FABRIC_RENDEZVOUS_PORT": "7444",
                "MNCS_FABRIC_RENDEZVOUS_CA": str(root / "env-ca.pem"),
                "MNCS_FABRIC_RENDEZVOUS_CERTIFICATE": str(root / "env-controller.pem"),
                "MNCS_FABRIC_RENDEZVOUS_KEY": str(root / "env-controller.key"),
                "MNCS_FABRIC_RENDEZVOUS_TRUST_STATE": str(root / "env-trust.jsonl"),
            }
            explicit = [
                "--rendezvous-host",
                "198.51.100.20",
                "--rendezvous-port",
                "8444",
                "--rendezvous-ca",
                str(root / "cli-ca.pem"),
                "--rendezvous-certificate",
                str(root / "cli-controller.pem"),
                "--rendezvous-key",
                str(root / "cli-controller.key"),
                "--rendezvous-trust-state",
                str(root / "cli-trust.jsonl"),
            ]
            with patch.dict(os.environ, environment):
                config = _controller_config(self._args(root, *explicit))
            self.assertEqual(config.rendezvous_host, "198.51.100.20")
            self.assertEqual(config.rendezvous_port, 8444)
            self.assertEqual(config.rendezvous_ca, root / "cli-ca.pem")

    def test_partial_rendezvous_environment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {"MNCS_FABRIC_RENDEZVOUS_HOST": "192.0.2.10"},
            ), self.assertRaises(ValidationError):
                _controller_config(self._args(root))

    def test_controller_identity_has_fabric_owned_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            args = build_parser().parse_args(["controller", "status"])
        self.assertEqual(args.controller_id, "mncs-fabric-controller")

    def test_enrollment_state_ownership_is_explicit(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["enrollment", "list"])
        online = parser.parse_args(
            ["enrollment", "list", "--admin-socket", "/tmp/admin.sock"]
        )
        self.assertEqual(online.admin_socket, Path("/tmp/admin.sock"))
        offline = parser.parse_args(
            ["enrollment", "list", "--offline-state", "/tmp/lifecycle.jsonl"]
        )
        self.assertEqual(offline.offline_state, Path("/tmp/lifecycle.jsonl"))
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "enrollment",
                    "issue",
                    "join.json",
                    "--ca",
                    "ca.pem",
                    "--ca-key",
                    "ca.key",
                    "--controller-certificate",
                    "controller.pem",
                    "--trust-state",
                    "trust.jsonl",
                    "--output",
                    "credentials.json",
                    "--admin-socket",
                    "/tmp/admin.sock",
                ]
            )


if __name__ == "__main__":
    unittest.main()
