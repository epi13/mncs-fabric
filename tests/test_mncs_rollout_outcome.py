"""Fabric rollout-outcome predicates in MNCS: agreement plus execution.

``mncs/fabric_rollout_outcome.mncs`` owns the pure outcome
classification from ``src/mncs_fabric/rollout.py``
(``deployment_succeeded``, ``canary_succeeded``, ``canary_failed``)
over host-reduced boolean/enum facts. Tests rebuild real outcome
dicts from the decoded reductions and prove Python agrees, then
execute.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.rollout import canary_failed, canary_succeeded, deployment_succeeded

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_rollout_outcome.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_rollout_outcome_corpus.json"

TXN_PY = {"Ready": "READY", "RolledBack": "ROLLED_BACK", "Other": "FAILED", "Absent": None}
MGMT_PY = {"Ready": "READY", "Quarantined": "QUARANTINED", "Intermediate": "MAINTENANCE", "Other": "BUSY"}


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


def _cert_deploy(present: bool, ok: bool) -> dict:
    if not present:
        return {}
    return {"disposition": "CERTIFIED" if ok else "FAILED"}


def _cert_canary(present: bool, ok: bool) -> dict:
    if not present:
        return {}
    return {"disposition": "CERTIFIED" if ok else "FAILED"}


class TestRolloutOutcomeCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            expected = case["expected"][0]["boolean"]["value"]
            if case["id"].startswith("deploy-"):
                restart, receipt_fail = _boolean(arguments[0]), _boolean(arguments[1])
                cert_present, cert_ok = _boolean(arguments[2]), _boolean(arguments[3])
                txn = TXN_PY[_finite_variant(arguments[4])]
                outcome = {
                    "restart_required": restart,
                    "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
                    "certification": _cert_deploy(cert_present, cert_ok),
                    "update_transaction": {} if txn is None else {"state": txn},
                }
                self.assertEqual(expected, deployment_succeeded(outcome), case["id"])
            elif case["id"].startswith("canary-"):
                restart, receipt_fail = _boolean(arguments[0]), _boolean(arguments[1])
                mgmt, txn = _finite_variant(arguments[2]), _finite_variant(arguments[3])
                cert_present, cert_ok = _boolean(arguments[4]), _boolean(arguments[5])
                blocking = _boolean(arguments[6])
                txn_state = TXN_PY[txn]
                outcome = {
                    "restart_required": restart,
                    "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
                    "management": {"state": MGMT_PY[mgmt]},
                    "update_transaction": {} if txn_state is None else {"state": txn_state},
                    "certification": _cert_canary(cert_present, cert_ok),
                    "conformance": {"blocking_failures": ["x"] if blocking else []},
                }
                self.assertEqual(expected, canary_succeeded(outcome), case["id"])
            elif case["id"].startswith("bad-"):
                receipt_fail, mgmt_quar = _boolean(arguments[0]), _boolean(arguments[1])
                disp_fail, obs_bad, txn_bad = (
                    _boolean(arguments[2]), _boolean(arguments[3]), _boolean(arguments[4]))
                outcome = {
                    "receipt": {"disposition": "FAIL" if receipt_fail else "PASS"},
                    "management": {"state": "QUARANTINED" if mgmt_quar else "READY"},
                    "disposition": "FAILED" if disp_fail else "PASS",
                    "observation": {"observation": "WRONG_VERSION" if obs_bad else "RECONNECTED"},
                    "update_transaction": {"state": "FAILED" if txn_bad else "READY"},
                }
                self.assertEqual(expected, canary_failed(outcome), case["id"])
            else:
                self.fail(f"corpus case has an unexpected id shape: {case['id']}")

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.rollout_outcome;", text)
        for entrypoint in ("fn candidate_deployment(", "fn candidate_canary(", "fn candidate_canary_bad("):
            self.assertIn(entrypoint, text)

    def test_canary_strictness_is_pinned(self) -> None:
        # A present-but-empty certification disposition passes deployment
        # yet fails the canary gate; the corpus pins both sides.
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        deploy = by_id["deploy-restart0-receipt0-certNone-txnREADY"]["expected"][0]["boolean"]["value"]
        self.assertTrue(deploy)


class TestRolloutOutcomeMncsExecution(unittest.TestCase):
    def test_toolchain_executes_rollout_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-rollout-") as tmp:
            completed = subprocess.run(
                [cli, "experiment", "run", str(SOURCE), "--backend", "research-bytecode",
                 "--corpus", str(CORPUS), "--output-dir", tmp],
                capture_output=True, text=True, timeout=3600,
            )
            self.assertEqual(completed.returncode, 0,
                             f"experiment run failed: {completed.stderr[-2000:]}")
            result = json.loads(completed.stdout)
            judgements = result.get("translation_validations", [])
            self.assertTrue(judgements, "experiment result carries no translation judgement")
            for judgement in judgements:
                self.assertEqual(judgement.get("judgement"), "PASS", judgement)
            corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
            cases = result.get("cases", [])
            self.assertEqual(len(cases), len(corpus["cases"]))
            failures = [item.get("case_id") for item in cases
                        if item.get("status") != "returned" or not item.get("expectation_met")]
            self.assertEqual(failures, [], f"MNCS execution disagrees with Python: {failures}")


if __name__ == "__main__":
    unittest.main()
