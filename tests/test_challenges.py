from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mncs_fabric.challenges import ChallengeReplayStore, bind_challenge_to_receipt, issue_execution_challenge, validate_execution_challenge, verify_replay_receipt
from mncs_fabric.executor import execute_local
from mncs_fabric.artifacts import build_manifest
from mncs_fabric.receipts import build_execution_receipt, execution_policy_identity_for_plan


class ChallengeTests(unittest.TestCase):
    def _receipt(self) -> dict[str, object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "task.py").write_text("print('challenge')\n", encoding="utf-8")
        manifest = build_manifest(root)
        plan = {"schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "challenge:job", "candidate_identity": "sha256:" + "a" * 64, "evaluator_identity": None, "artifact_manifest_identity": manifest["manifest_identity"], "argv": ["@python", "task.py"], "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096, "environment": {}, "required_capabilities": ["python"], "result_paths": [], "network_policy": "DECLARED_OFFLINE"}
        challenge = issue_execution_challenge(issuer_identity="fabric-controller-01", scope={"subject_identity": "a" * 64, "candidate_id": "candidate-" + "a" * 64, "bundle_identity": manifest["manifest_identity"][7:], "execution_policy_identity": execution_policy_identity_for_plan(plan), "runner_identity": "mncs-fabric-local-runner-v1"}, ttl_seconds=60).challenge
        assert challenge is not None
        self._challenge = challenge
        record = execute_local(plan, root, manifest, "challenge-node")
        return build_execution_receipt(record, challenge=challenge)

    def test_issue_bind_consume_restart_and_verify(self) -> None:
        receipt = self._receipt()
        challenge = self._challenge
        issued_at = datetime.fromisoformat(challenge["issued_at"].replace("Z", "+00:00"))
        self.assertEqual(bind_challenge_to_receipt(challenge, receipt).category, "PASS")
        store_path = Path(tempfile.mkdtemp()) / "replay.jsonl"
        first = ChallengeReplayStore(store_path).consume(challenge, receipt, now=issued_at + timedelta(seconds=1))
        self.assertEqual(first.category, "PASS")
        assert first.replay_receipt is not None
        second = ChallengeReplayStore(store_path).consume(challenge, receipt, now=issued_at + timedelta(seconds=2))
        self.assertEqual(second.category, "FAIL")
        self.assertEqual(verify_replay_receipt(first.replay_receipt, challenge, receipt, store=ChallengeReplayStore(store_path)).category, "PASS")

    def test_scope_substitution_and_future_version_fail_closed(self) -> None:
        receipt = self._receipt()
        challenge = self._challenge
        mutated = copy.deepcopy(receipt)
        mutated["subject"] = copy.deepcopy(mutated["subject"])  # type: ignore[index]
        mutated["subject"]["candidate_id"] = "candidate-substitute"  # type: ignore[index]
        self.assertEqual(bind_challenge_to_receipt(challenge, mutated).category, "FAIL")
        forged = copy.deepcopy(receipt)
        forged["receipt_identity"] = receipt["receipt_identity"]
        forged["challenge"] = copy.deepcopy(forged["challenge"])
        forged["challenge"]["nonce"] = "A" * 43  # type: ignore[index]
        self.assertEqual(bind_challenge_to_receipt(challenge, forged).category, "FAIL")
        future = copy.deepcopy(challenge)
        future["schema_version"] = "0.2-experimental"
        self.assertEqual(validate_execution_challenge(future).category, "UNKNOWN")
