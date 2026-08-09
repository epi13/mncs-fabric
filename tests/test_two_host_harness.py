from __future__ import annotations

import unittest
from pathlib import Path

from scripts.two_host_fedora_test import build_parser, _shell_quote


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
