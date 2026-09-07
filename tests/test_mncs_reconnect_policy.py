"""Fabric reconnect-observation core in MNCS: corpus agreement plus compiled execution.

``mncs/fabric_reconnect.mncs`` owns the pure classification inside
``src/mncs_fabric/update_lifecycle.py::observe_reconnect``: given the
transaction state plus already validated boolean facts, which observation
was made and which state follows. These tests prove the Python authority
and the MNCS module agree:

- the checked-in corpus expectations match ``observe_reconnect`` over
  real transactions (always runs; guards corpus drift), and
- the MNCS toolchain executes the module over the whole corpus and its
  judgement is PASS (runs when the language CLI is available; the CI
  ``mncs-conformance`` job builds it at a pinned revision).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.update_lifecycle import (
    build_update_transaction,
    observe_reconnect,
    version_matches_expected,
)
from mncs_fabric.versioning import parse_fabric_version

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_reconnect.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_reconnect_corpus.json"
GEN = REPO_ROOT / "mncs" / "gen_reconnect_corpus.py"

STATE_PY = {
    "DisconnectExpected": "DISCONNECT_EXPECTED",
    "Reconnecting": "RECONNECTING",
    "VersionVerifying": "VERSION_VERIFYING",
    "Other": "READY",
}
OTHER_STATES = ["READY", "FAILED", "CERTIFYING"]
EXPECTED_VERSION = "0.2.0a31"
EXPECTED_ARTIFACT = "sha256:" + "ab" * 32
DEADLINE = "2030-01-01T00:00:00Z"
NOW_FRESH = "2029-06-01T00:00:00Z"
NOW_EXPIRED = "2031-06-01T00:00:00Z"

OBS_PY = {
    "AwaitingDisconnect": "AWAITING_DISCONNECT",
    "ExpectedDisconnect": "EXPECTED_DISCONNECT",
    "AwaitingReconnect": "AWAITING_RECONNECT",
    "Reconnected": "RECONNECTED",
    "DeadlineExpired": "DEADLINE_EXPIRED",
    "WrongIdentity": "WRONG_IDENTITY",
    "WrongVersion": "WRONG_VERSION",
    "StillConnected": "STILL_CONNECTED",
    "MalformedVersion": "MALFORMED_VERSION",
}
NEXT_PY = {
    "DisconnectExpected": "DISCONNECT_EXPECTED",
    "Reconnecting": "RECONNECTING",
    "VersionVerifying": "VERSION_VERIFYING",
    "Certifying": "CERTIFYING",
    "RollbackApplying": "ROLLBACK_APPLYING",
    "Failed": "FAILED",
    "Quarantined": "QUARANTINED",
    "Other": None,
}


def _find_language_cli() -> str | None:
    explicit = os.environ.get("MNCS_LANGUAGE_CLI")
    if explicit and Path(explicit).is_file():
        return explicit
    sibling = REPO_ROOT.parent / "mncs-language" / "target" / "debug" / "mncs"
    if sibling.is_file():
        return str(sibling)
    return None


def _finite_variant(argument: dict) -> str:
    return str(argument["finite"]["variant_identity"].rsplit("::", 1)[1])


def _boolean(argument: dict) -> bool:
    return bool(argument["boolean"]["value"])


def _reduce(arguments: list[dict]) -> dict[str, object]:
    return {
        "state": _finite_variant(arguments[0]),
        "expired": _boolean(arguments[1]),
        "connected": _boolean(arguments[2]),
        "seen_disconnect": _boolean(arguments[3]),
        "same_identity": _boolean(arguments[4]),
        "version_matched": _boolean(arguments[5]),
        "version_malformed": _boolean(arguments[6]),
        "recovery": _boolean(arguments[7]),
        "present_at_expected": _boolean(arguments[8]),
    }


def _rebuild_transaction(reduced: dict[str, object]):
    state_mncs = reduced["state"]
    state = STATE_PY[state_mncs]
    now = NOW_EXPIRED if reduced["expired"] else NOW_FRESH
    if state_mncs == "Other":
        # The MNCS module folds every inapplicable state to Other; rebuild
        # with a representative so the Python oracle runs the same arm.
        state = "READY"
    connected = reduced["connected"]
    if reduced["present_at_expected"] and reduced["version_matched"]:
        observed_id: str | None = "worker-alpha"
        observed_version: str | None = EXPECTED_VERSION
        observed_artifact: str | None = EXPECTED_ARTIFACT
    elif (
        reduced["present_at_expected"]
        and reduced["same_identity"]
        and not reduced["version_malformed"]
    ):
        # Artifact-clash shape: the version matches (so the recovery
        # formula holds) but the observed artifact contradicts the
        # transaction, which is exactly what `version_matched=False`
        # folds. Rebuild the clash, not a version mismatch.
        observed_id = "worker-alpha"
        observed_version = EXPECTED_VERSION
        observed_artifact = "sha256:" + "cd" * 32
    elif not connected:
        observed_id = None
        observed_version = None
        observed_artifact = None
    elif not reduced["same_identity"]:
        observed_id = "worker-beta"
        observed_version = EXPECTED_VERSION
        observed_artifact = None
    elif reduced["version_malformed"]:
        observed_id = "worker-alpha"
        observed_version = "banana"
        observed_artifact = None
    elif not reduced["version_matched"]:
        observed_id = "worker-alpha"
        observed_version = "0.2.0a30"
        observed_artifact = None
    else:
        observed_id = "worker-alpha"
        observed_version = EXPECTED_VERSION
        observed_artifact = EXPECTED_ARTIFACT
    transaction = build_update_transaction(
        worker_id="worker-alpha",
        state=state,
        expected_version=EXPECTED_VERSION,
        previous_version="0.2.0a30",
        artifact_identity=EXPECTED_ARTIFACT,
        previous_artifact_identity=None,
        deadline=DEADLINE,
        reason="agreement check",
    )
    return transaction, {
        "connected": connected,
        "seen_disconnect": reduced["seen_disconnect"],
        "observed_worker_id": observed_id,
        "observed_version": observed_version,
        "observed_artifact_identity": observed_artifact,
        "now": now,
        "recovery": reduced["recovery"],
    }


class TestReconnectCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            reduced = _reduce(arguments)
            transaction, evidence = _rebuild_transaction(reduced)
            result = observe_reconnect(transaction, **evidence)
            if case["id"].startswith("obs-"):
                expected = OBS_PY[_finite_variant(case["expected"][0])]
                self.assertEqual(expected, result["observation"], case["id"])
            elif case["id"].startswith("next-"):
                variant = _finite_variant(case["expected"][0])
                if reduced["state"] == "Other":
                    # Reduction pin: inapplicable states always yield Other.
                    self.assertEqual(variant, "Other", case["id"])
                    self.assertEqual(result["next_state"], transaction["state"], case["id"])
                else:
                    self.assertEqual(NEXT_PY[variant], result["next_state"], case["id"])
            else:
                self.fail(f"corpus case has an unexpected id shape: {case['id']}")

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.reconnect;", text)
        self.assertIn("fn candidate_observation(", text)
        self.assertIn("fn candidate_next(", text)

    def test_recovery_resumes_at_version_verification(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        key = "next-DISCONNECT_EXPECTED-exp0-conn1-seen1-rec1-present1"
        self.assertEqual(_finite_variant(by_id[key]["expected"][0]), "VersionVerifying", key)
        obs = _finite_variant(by_id["obs-" + key.removeprefix("next-")]["expected"][0])
        self.assertEqual(obs, "Reconnected", key)


class TestReconnectMncsExecution(unittest.TestCase):
    def test_toolchain_executes_reconnect_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-reconnect-") as tmp:
            completed = subprocess.run(
                [
                    cli,
                    "experiment",
                    "run",
                    str(SOURCE),
                    "--backend",
                    "research-bytecode",
                    "--corpus",
                    str(CORPUS),
                    "--output-dir",
                    tmp,
                ],
                capture_output=True,
                text=True,
                timeout=3600,
            )
            self.assertEqual(
                completed.returncode,
                0,
                f"experiment run failed: {completed.stderr[-2000:]}",
            )
            result = json.loads(completed.stdout)
            judgements = result.get("translation_validations", [])
            self.assertTrue(judgements, "experiment result carries no translation judgement")
            for judgement in judgements:
                self.assertEqual(judgement.get("judgement"), "PASS", judgement)
            corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
            cases = result.get("cases", [])
            self.assertEqual(len(cases), len(corpus["cases"]))
            failures = [
                item.get("case_id")
                for item in cases
                if item.get("status") != "returned" or not item.get("expectation_met")
            ]
            self.assertEqual(failures, [], f"MNCS execution disagrees with Python: {failures}")


if __name__ == "__main__":
    unittest.main()
