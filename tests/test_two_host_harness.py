from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from scripts.two_host_fedora_test import build_parser, _shell_quote
from scripts.two_host_fedora_test import Remote
from scripts.two_host_windows_gpu_test import build_parser as build_windows_parser


class TwoHostHarnessTests(unittest.TestCase):
    def test_operator_parameters_are_explicit_and_shell_arguments_are_quoted(self) -> None:
        args = build_parser().parse_args(["--ssh-host", "192.0.2.10", "--ssh-user", "fabric", "--ssh-key", "/tmp/key", "--worker-host", "192.0.2.10", "--expected-hostname", "fabric-worker-01", "--output", "/tmp/evidence"])
        self.assertEqual(args.worker_port, 7443)
        self.assertIn("'fabric worker'", _shell_quote("fabric worker"))

    def test_harness_does_not_encode_an_ssh_tunnel_or_default_address(self) -> None:
        parser_text = build_parser().format_help()
        self.assertIn("--worker-host", parser_text)
        self.assertIn("--ssh-key", parser_text)
        source = Path(__file__).parents[1].joinpath("scripts", "two_host_fedora_test.py").read_text(encoding="utf-8")
        self.assertIn('"StrictHostKeyChecking=yes"', source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertNotIn("UserKnownHostsFile=/dev/null", source)
        self.assertNotIn("ssh -L", source)
        self.assertNotIn("ExitOnForwardFailure", source)
        self.assertIn("remote_worker_launcher.py", source)

    def test_alias_bootstrap_keeps_public_key_only_transport(self) -> None:
        remote = Remote(alias="explicit-pi")
        self.assertEqual(remote.destination, "explicit-pi")
        self.assertIn("IdentitiesOnly=no", remote.options)
        self.assertIn("PreferredAuthentications=publickey", remote.options)
        self.assertIn("PasswordAuthentication=no", remote.options)
        self.assertNotIn("-i", remote.options)

    def test_remote_ssh_timeout_is_bounded_and_overrideable(self) -> None:
        self.assertEqual(inspect.signature(Remote.ssh).parameters["timeout"].default, 20)

    def test_windows_harness_requires_explicit_endpoint_and_stays_out_of_band(self) -> None:
        parser_text = build_windows_parser().format_help()
        self.assertIn("--ssh-host", parser_text)
        self.assertIn("--expected-hostname", parser_text)
        source = Path(__file__).parents[1].joinpath("scripts", "two_host_windows_gpu_test.py").read_text(encoding="utf-8")
        self.assertNotIn("192.168.1.16", source)
        self.assertIn('"StrictHostKeyChecking=yes"', source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertNotIn("ssh -L", source)
