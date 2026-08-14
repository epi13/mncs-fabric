import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.containment import BubblewrapProvider
from mncs_fabric.executor import _minimal_environment, execute_local


def identity(char: str) -> str:
    return "sha256:" + char * 64


def plan(manifest_identity: str, *, timeout=5, limit=4096, result_paths=None):
    return {
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "test:job",
        "candidate_identity": identity("a"),
        "evaluator_identity": None,
        "artifact_manifest_identity": manifest_identity,
        "argv": ["@python", "task.py"],
        "working_directory": ".",
        "timeout_seconds": timeout,
        "output_limit_bytes": limit,
        "environment": {"PYTHONHASHSEED": "0"},
        "required_capabilities": ["python"],
        "result_paths": result_paths or [],
        "network_policy": "DECLARED_OFFLINE",
    }


class ExecutorTests(unittest.TestCase):
    def _run(
        self,
        source: str,
        *,
        containment_mode: str = "compatibility-uncontained",
        containment_provider: BubblewrapProvider | None = None,
        **plan_kwargs,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text(source, encoding="utf-8")
        manifest = build_manifest(root)
        return execute_local(
            plan(manifest["manifest_identity"], **plan_kwargs),
            root,
            manifest,
            "test-node",
            containment_mode=containment_mode,
            containment_provider=containment_provider,
        )

    def test_pass_and_result_capture(self):
        record = self._run('from pathlib import Path\nPath("result.txt").write_text("ok", encoding="utf-8")\nprint("done")\n', result_paths=["result.txt"])
        self.assertEqual(record["outcome"], "PASS")
        self.assertEqual(record["termination_reason"], "COMPLETED")
        self.assertEqual(record["results"][0]["path"], "result.txt")

    def test_nonzero_is_fail(self):
        record = self._run('raise SystemExit(7)\n')
        self.assertEqual(record["outcome"], "FAIL")
        self.assertEqual(record["termination_reason"], "NONZERO_EXIT")

    def test_timeout_is_unknown(self):
        record = self._run('import time\ntime.sleep(3)\n', timeout=0.1)
        self.assertEqual(record["outcome"], "UNKNOWN")
        self.assertEqual(record["termination_reason"], "TIMEOUT")

    def test_output_limit_is_unknown(self):
        record = self._run('print("x" * 10000)\n', limit=128)
        self.assertEqual(record["outcome"], "UNKNOWN")
        self.assertEqual(record["termination_reason"], "OUTPUT_LIMIT")

    def test_bounded_environment_retains_platform_user_identity(self):
        original = {key: os.environ.get(key) for key in ("USERNAME", "USER", "LOGNAME")}
        try:
            os.environ["USERNAME"] = "fabric-test-user"
            os.environ["USER"] = "fabric-test-user"
            os.environ["LOGNAME"] = "fabric-test-user"
            environment = _minimal_environment({})
        finally:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(environment["USERNAME"], "fabric-test-user")
        self.assertEqual(environment["USER"], "fabric-test-user")
        self.assertEqual(environment["LOGNAME"], "fabric-test-user")

    def test_required_containment_fails_closed_when_provider_is_unavailable(self):
        record = self._run(
            'print("must not run")\n',
            containment_mode="required",
            containment_provider=BubblewrapProvider("/definitely/missing/bwrap"),
        )
        self.assertEqual(record["outcome"], "UNKNOWN")
        self.assertEqual(record["termination_reason"], "CONTAINMENT_UNAVAILABLE")

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap is not installed")
    def test_bubblewrap_confines_filesystem_and_offline_network(self):
        provider = BubblewrapProvider()
        if not provider.user_namespace_available():
            record = self._run(
                'print("must not run")\n',
                containment_mode="required",
                containment_provider=provider,
            )
            self.assertEqual(record["outcome"], "UNKNOWN", record.get("detail"))
            self.assertEqual(record["termination_reason"], "CONTAINMENT_UNAVAILABLE")
            self.assertIn("user namespace", record["detail"] or "")
            return
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        root = parent / "bundle"
        root.mkdir()
        outside = parent / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        (root / "task.py").write_text(
            "from pathlib import Path\n"
            "import socket\n"
            f"outside = Path({str(outside)!r})\n"
            "print(f'outside_read={outside.exists()}')\n"
            "try:\n"
            "    outside.write_text('changed')\n"
            "    print('outside_write=True')\n"
            "except OSError:\n"
            "    print('outside_write=False')\n"
            "try:\n"
            f"    socket.create_connection(('127.0.0.1', {port}), timeout=0.2)\n"
            "    print('network=True')\n"
            "except OSError:\n"
            "    print('network=False')\n"
            "Path('result.txt').write_text('ok')\n",
            encoding="utf-8",
        )
        manifest = build_manifest(root)
        record = execute_local(
            plan(manifest["manifest_identity"], result_paths=["result.txt"]),
            root,
            manifest,
            "test-node",
            containment_mode="required",
        )
        self.assertEqual(record["outcome"], "PASS", record.get("detail"))
        self.assertIn("outside_read=False", record["stdout"]["captured_utf8"])
        self.assertIn("outside_write=False", record["stdout"]["captured_utf8"])
        self.assertIn("network=False", record["stdout"]["captured_utf8"])
        self.assertEqual(outside.read_text(encoding="utf-8"), "secret")
        self.assertEqual(
            record["policy_observations"]["filesystem_enforcement"],
            "BUBBLEWRAP_BUNDLE_ONLY",
        )
        self.assertEqual(
            record["policy_observations"]["network_enforcement"],
            "BUBBLEWRAP_NETWORK_NAMESPACE",
        )
