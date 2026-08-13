from __future__ import annotations

import json
from pathlib import Path
import unittest
from datetime import datetime, timedelta, timezone

from mncs_fabric.capabilities import build_capability_observation
from mncs_fabric.canonical import sha256_identity
from mncs_fabric.contracts import ConsumerContext
from mncs_fabric.api import FabricClient
from mncs_fabric.errors import ValidationError
from mncs_fabric.targets import (
    EXECUTION_TARGET_SCHEMA,
    TARGET_AUTHORIZATION_INTERPRETATION,
    TARGET_CLAIM_BOUNDARY,
    ExecutionTargetReference,
    build_target_execution_evidence,
    evaluate_target_admission,
    validate_target_admission,
    validate_target_execution_evidence,
    validate_execution_target_reference,
)


class ExecutionTargetReferenceTests(unittest.TestCase):
    def _admission_inputs(self):
        now = datetime.now(timezone.utc)
        context = ConsumerContext(
            source_project="test-harness",
            consumer_workload_identity="sha256:" + "9" * 64,
        )
        capability = build_capability_observation(
            worker_identity="worker-a",
            capabilities=[
                {"kind": "runtime", "namespace": "system", "name": "python", "version": "3.13"},
                {"kind": "tool", "namespace": "system", "name": "git", "version": "2.51"},
            ],
            captured_at=now.isoformat().replace("+00:00", "Z"),
        )
        tool_identity = next(
            item["capability_identity"]
            for item in capability["capabilities"]
            if item["kind"] == "tool"
        )
        runtime_identity = "sha256:" + "8" * 64
        target = ExecutionTargetReference(
            worker_identity="worker-a",
            required_capabilities=("python", "tool:git"),
            tool_capability_identity=tool_identity,
            runtime_identity=runtime_identity,
            consumer_context_identity=context.context_identity,
            consumer_authorization_identity="sha256:" + "7" * 64,
            liveness_max_age_seconds=30,
            capability_max_age_seconds=30,
        ).to_dict()
        worker = {
            "worker_id": "worker-a",
            "membership_status": "ENROLLED",
            "availability": "AVAILABLE",
            "transport": "worker-initiated-tls-rendezvous",
            "session_id": "session-a",
            "session_generation": 3,
            "last_seen": now.isoformat().replace("+00:00", "Z"),
            "description": {"runtime_profile": {"runtime_profile_identity": runtime_identity}},
        }
        kwargs = {
            "worker_state": worker,
            "capability_observation": capability,
            "consumer_context": context.to_dict(),
            "consumer_authorization_identity": target["consumer_authorization_identity"],
            "authenticated_client_identity": "sha256:" + "6" * 64,
            "client_label": "harness",
            "request_identity": "sha256:" + "5" * 64,
            "execution_request_identity": "sha256:" + "4" * 64,
            "job_identity": "sha256:" + "3" * 64,
            "bundle_identity": "2" * 64,
            "now": now.isoformat().replace("+00:00", "Z"),
        }
        return target, kwargs, now

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

    def test_target_admission_and_execution_evidence_bind_exact_facts(self) -> None:
        target, kwargs, _now = self._admission_inputs()
        admission = evaluate_target_admission(target, **kwargs)
        self.assertEqual(admission["disposition"], "PASS")
        self.assertEqual(admission["reason_code"], "TARGET_ADMITTED")
        self.assertEqual(
            admission["authorization_interpretation"],
            TARGET_AUTHORIZATION_INTERPRETATION,
        )
        self.assertEqual(validate_target_admission(admission), admission)
        result = {
            "worker_identity": "worker-a",
            "bundle_identity": "2" * 64,
            "job_identity": "sha256:" + "3" * 64,
            "record_identity": "sha256:" + "1" * 64,
            "receipt_identity": "0" * 64,
            "disposition": "EXECUTED",
        }
        evidence = build_target_execution_evidence(admission, result)
        self.assertEqual(validate_target_execution_evidence(evidence), evidence)
        self.assertEqual(admission["target_reference"], target)
        self.assertEqual(evidence["session_generation"], 3)
        self.assertEqual(
            evidence["authenticated_client_identity"],
            kwargs["authenticated_client_identity"],
        )
        self.assertEqual(
            evidence["consumer_authorization_identity"],
            target["consumer_authorization_identity"],
        )
        root = Path(__file__).parents[1] / "schemas"
        admission_schema = json.loads(
            (root / "target-admission-v0.1.schema.json").read_text(encoding="utf-8")
        )
        evidence_schema = json.loads(
            (root / "target-execution-evidence-v0.1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(admission), set(admission_schema["required"]))
        self.assertEqual(set(admission), set(admission_schema["properties"]))
        self.assertEqual(set(evidence), set(evidence_schema["required"]))
        self.assertEqual(set(evidence), set(evidence_schema["properties"]))

        contradictory = {**admission, "disposition": "UNKNOWN"}
        contradictory["target_admission_identity"] = sha256_identity(
            {key: value for key, value in contradictory.items() if key != "target_admission_identity"}
        )
        with self.assertRaisesRegex(ValidationError, "disposition"):
            validate_target_admission(contradictory)
        with self.assertRaisesRegex(ValidationError, "job differs"):
            build_target_execution_evidence(
                admission,
                {**result, "job_identity": "sha256:" + "f" * 64},
            )

    def test_target_admission_failure_codes_are_stable_and_never_fallback(self) -> None:
        target, kwargs, now = self._admission_inputs()

        cases = []
        cases.append(("TARGET_UNKNOWN", {**kwargs, "worker_state": None}))
        cases.append(("TARGET_REVOKED", {**kwargs, "worker_state": {**kwargs["worker_state"], "membership_status": "REVOKED"}}))
        cases.append(("TARGET_DISCONNECTED", {**kwargs, "worker_state": {**kwargs["worker_state"], "availability": "UNAVAILABLE"}}))
        stale_worker = {
            **kwargs["worker_state"],
            "last_seen": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        }
        cases.append(("TARGET_LIVENESS_STALE", {**kwargs, "worker_state": stale_worker}))
        stale_capability = build_capability_observation(
            worker_identity="worker-a",
            capabilities=[{"kind": "runtime", "namespace": "system", "name": "python"}],
            captured_at=(now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        )
        cases.append(("TARGET_CAPABILITIES_STALE", {**kwargs, "capability_observation": stale_capability}))
        missing = build_capability_observation(
            worker_identity="worker-a",
            capabilities=[{"kind": "runtime", "namespace": "system", "name": "python"}],
            captured_at=now.isoformat().replace("+00:00", "Z"),
        )
        cases.append(("TARGET_CAPABILITY_MISSING", {**kwargs, "capability_observation": missing}))
        wrong_runtime = {**kwargs["worker_state"], "description": {"runtime_profile": {"runtime_profile_identity": "sha256:" + "0" * 64}}}
        cases.append(("TARGET_RUNTIME_MISMATCH", {**kwargs, "worker_state": wrong_runtime}))
        tool_target = dict(target)
        tool_target["tool_capability_identity"] = "sha256:" + "f" * 64
        tool_target["target_identity"] = sha256_identity(
            {key: value for key, value in tool_target.items() if key != "target_identity"}
        )
        cases.append(("TARGET_TOOL_CAPABILITY_MISMATCH", {**kwargs, "target": tool_target}))
        other_context = ConsumerContext(source_project="other", consumer_workload_identity="sha256:" + "e" * 64)
        cases.append(("TARGET_CONTEXT_MISMATCH", {**kwargs, "consumer_context": other_context.to_dict()}))
        cases.append(("TARGET_AUTHORIZATION_BINDING_INVALID", {**kwargs, "consumer_authorization_identity": "sha256:" + "d" * 64}))

        for expected, values in cases:
            selected_target = values.pop("target", target)
            admission = evaluate_target_admission(selected_target, **values)
            self.assertEqual(admission["reason_code"], expected)
            self.assertNotEqual(admission["disposition"], "PASS")
            self.assertEqual(selected_target["fallback_policy"], "NONE")


if __name__ == "__main__":
    unittest.main()
