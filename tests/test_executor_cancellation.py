"""Cooperative cancellation at the execution boundary.

A set ``threading.Event`` passed as ``cancel_event`` terminates the child
process tree and reports ``termination_reason`` ``CANCELLED`` with outcome
``UNKNOWN``. Cancellation is never semantic FAIL; these tests pin that
contract plus the phase semantics (before spawn, mid-run, after completion,
repeated) and verify no orphaned child survives a mid-run cancel.
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.executor import execute_local
from tests.test_executor import plan


def _live_pids_with_cmdline_marker(marker: str) -> list[int]:
    found = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return found
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace"
            )
        except OSError:
            continue
        if marker in cmdline and int(entry.name) != os.getpid():
            found.append(int(entry.name))
    return found


class ExecutorCancellationTests(unittest.TestCase):
    def _run_cancel(
        self,
        source: str,
        event: threading.Event,
        *,
        timeout: int = 60,
        results: dict | None = None,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text(source, encoding="utf-8")
        manifest = build_manifest(root)
        if results is not None:
            results["bundle"] = str(root)
        return execute_local(
            plan(manifest["manifest_identity"], timeout=timeout),
            root,
            manifest,
            "test-node",
            cancel_event=event,
        )

    def test_cancel_mid_run_reports_cancelled_unknown(self):
        event = threading.Event()
        outcome: dict = {}

        def target():
            outcome["record"] = self._run_cancel(
                "import time\ntime.sleep(30)\n", event, results=outcome
            )

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        time.sleep(2.0)
        event.set()
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        record = outcome["record"]
        self.assertEqual(record["termination_reason"], "CANCELLED")
        # Cancellation is operational UNKNOWN, never semantic FAIL.
        self.assertEqual(record["outcome"], "UNKNOWN")
        self.assertTrue(record["record_id"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires /proc")
    def test_no_orphan_after_cancel(self):
        event = threading.Event()
        outcome: dict = {}

        def target():
            outcome["record"] = self._run_cancel(
                "import time\ntime.sleep(30)\n", event, results=outcome
            )

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        time.sleep(2.0)
        event.set()
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcome["record"]["termination_reason"], "CANCELLED")
        deadline = time.monotonic() + 10.0
        lingering = _live_pids_with_cmdline_marker(outcome["bundle"])
        while lingering and time.monotonic() < deadline:
            time.sleep(0.2)
            lingering = _live_pids_with_cmdline_marker(outcome["bundle"])
        self.assertEqual(lingering, [])

    def test_preset_event_cancels_before_spawn(self):
        event = threading.Event()
        event.set()
        started = time.monotonic()
        # Build the record through the public path with the event pre-set.
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text("print('never runs')\n", encoding="utf-8")
        manifest = build_manifest(root)
        record = execute_local(
            plan(manifest["manifest_identity"]),
            root,
            manifest,
            "test-node",
            cancel_event=event,
        )
        self.assertEqual(record["termination_reason"], "CANCELLED")
        self.assertEqual(record["outcome"], "UNKNOWN")
        self.assertIsNone(record["resolved_executable"])
        self.assertLess(time.monotonic() - started, 30)

    def test_late_cancel_is_noop(self):
        event = threading.Event()
        record_holder: dict = {}

        def target():
            record_holder["record"] = self._run_cancel("print('done')\n", event)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        # The child already completed; setting the event afterwards changes nothing.
        event.set()
        record = record_holder["record"]
        self.assertEqual(record["termination_reason"], "COMPLETED")
        self.assertEqual(record["outcome"], "PASS")

    def test_repeated_cancel_is_idempotent(self):
        event = threading.Event()
        outcome: dict = {}

        def target():
            outcome["record"] = self._run_cancel(
                "import time\ntime.sleep(30)\n", event
            )

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        time.sleep(2.0)
        event.set()
        event.set()
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        record = outcome["record"]
        self.assertEqual(record["termination_reason"], "CANCELLED")
        self.assertEqual(record["outcome"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
