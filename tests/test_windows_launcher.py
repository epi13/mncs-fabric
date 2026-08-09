from __future__ import annotations

import os
import sys
import unittest

from scripts.windows_worker_launcher import _identity, _token, build_parser


class WindowsLauncherTests(unittest.TestCase):
    def test_process_token_is_not_a_name_based_probe(self) -> None:
        token = _token(os.getpid())
        if os.name == "nt":
            self.assertIsNotNone(token)
        else:
            self.assertIsNotNone(token) if os.path.exists(f"/proc/{os.getpid()}") else self.assertIsNone(token)
        self.assertNotEqual(_identity([sys.executable, "-m", "mncs_fabric"]), _identity([sys.executable, "-c", "pass"]))

    def test_launcher_requires_explicit_bounded_command(self) -> None:
        args = build_parser().parse_args(["start", "--state", "state.json", "--worker-id", "worker", "--stdout", "out.log", "--stderr", "err.log", "--", sys.executable, "-m", "mncs_fabric"])
        self.assertEqual(args.worker_id, "worker")
        self.assertEqual(args.command[-2:], ["-m", "mncs_fabric"])


if __name__ == "__main__":
    unittest.main()
