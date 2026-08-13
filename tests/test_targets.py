from __future__ import annotations

import json
from pathlib import Path
import unittest

from mncs_fabric.api import FabricClient
from mncs_fabric.errors import ValidationError
from mncs_fabric.targets import (
    EXECUTION_TARGET_SCHEMA,
    TARGET_CLAIM_BOUNDARY,
    ExecutionTargetReference,
    validate_execution_target_reference,
)


class ExecutionTargetReferenceTests(unittest.TestCase):
    def test_reference_is_canonical_identity_addressed_and_public(self) -> None:
        target = ExecutionTargetReference(
            worker_identity="worker-build-a",
            required_capabilities=("tool:git", "python"),
            tool_capability_identity="sha256:" + "a" * 64,
            runtime_identity="sha256:" + "b" * 64,
            consumer_context_identity="sha256:" + "c" * 64,
            consumer_authorization_identity="sha256:" + "d" * 64,
        )
        value = target.to_dict()
        self.assertEqual(value["schema_version"], EXECUTION_TARGET_SCHEMA)
        self.assertEqual(value["required_capabilities"], ["python", "tool:git"])
        self.assertTrue(value["require_current_membership"])
        self.assertTrue(value["require_authenticated_presence"])
        self.assertEqual(value["fallback_policy"], "NONE")
        self.assertEqual(value["claim_boundary"], TARGET_CLAIM_BOUNDARY)
        self.assertEqual(validate_execution_target_reference(value), value)
        contract = FabricClient.contract()
        self.assertTrue(contract["features"]["execution_target_reference"])
        self.assertEqual(contract["execution_target_reference_schema"], EXECUTION_TARGET_SCHEMA)

    def test_reference_rejects_tamper_wrong_bindings_and_fallback(self) -> None:
        value = ExecutionTargetReference(
            worker_identity="worker-a",
            required_capabilities=("python",),
            consumer_context_identity="sha256:" + "1" * 64,
            consumer_authorization_identity="sha256:" + "2" * 64,
        ).to_dict()
        with self.assertRaisesRegex(ValidationError, "another worker"):
            validate_execution_target_reference(value, expected_worker_identity="worker-b")
        with self.assertRaisesRegex(ValidationError, "another consumer"):
            validate_execution_target_reference(
                value, expected_consumer_context_identity="sha256:" + "3" * 64
            )
        changed = dict(value)
        changed["fallback_policy"] = "LOCAL"
        with self.assertRaisesRegex(ValidationError, "identity"):
            validate_execution_target_reference(changed)

    def test_reference_has_no_semantic_or_shell_authority_fields(self) -> None:
        value = ExecutionTargetReference(
            worker_identity="worker-a",
            required_capabilities=("python",),
            consumer_context_identity="sha256:" + "4" * 64,
            consumer_authorization_identity="sha256:" + "5" * 64,
        ).to_dict()
        for forbidden in ("tool_choice", "argv", "shell", "ssh", "hostname", "verdict"):
            changed = dict(value)
            changed[forbidden] = "forbidden"
            with self.assertRaisesRegex(ValidationError, "fields"):
                validate_execution_target_reference(changed)

    def test_json_schema_has_exact_runtime_fields(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas" / "execution-target-reference-v0.1.schema.json")
            .read_text(encoding="utf-8")
        )
        value = ExecutionTargetReference(
            worker_identity="worker-a",
            required_capabilities=("python",),
            consumer_context_identity="sha256:" + "6" * 64,
            consumer_authorization_identity="sha256:" + "7" * 64,
        ).to_dict()
        self.assertEqual(set(value), set(schema["required"]))
        self.assertEqual(set(value), set(schema["properties"]))


if __name__ == "__main__":
    unittest.main()
