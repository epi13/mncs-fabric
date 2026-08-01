import unittest

from mncs_fabric.errors import ValidationError
from mncs_fabric.models import validate_job_plan


def base_plan():
    return {
        "schema_version": "mncs-fabric.job-plan.v0.1",
        "job_id": "test:plan",
        "candidate_identity": "sha256:" + "a" * 64,
        "evaluator_identity": None,
        "artifact_manifest_identity": "sha256:" + "b" * 64,
        "argv": ["@python", "task.py"],
        "working_directory": ".",
        "timeout_seconds": 5,
        "output_limit_bytes": 1024,
        "environment": {},
        "required_capabilities": ["python"],
        "result_paths": ["result.json"],
        "network_policy": "UNSPECIFIED",
    }


class ModelTests(unittest.TestCase):
    def test_relative_executable_is_rejected(self):
        value = base_plan()
        value["argv"] = ["python", "task.py"]
        with self.assertRaises(ValidationError):
            validate_job_plan(value)

    def test_result_traversal_is_rejected(self):
        value = base_plan()
        value["result_paths"] = ["../result.json"]
        with self.assertRaises(ValidationError):
            validate_job_plan(value)

    def test_identity_is_derived(self):
        value = validate_job_plan(base_plan())
        self.assertTrue(value["job_identity"].startswith("sha256:"))
