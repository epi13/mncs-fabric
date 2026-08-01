import tempfile
import unittest
from pathlib import Path

from mncs_fabric.artifacts import build_manifest
from mncs_fabric.executor import execute_local


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
    def _run(self, source: str, **plan_kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text(source, encoding="utf-8")
        manifest = build_manifest(root)
        return execute_local(plan(manifest["manifest_identity"], **plan_kwargs), root, manifest, "test-node")

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
