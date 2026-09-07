"""Fabric enrollment-status lattice in MNCS: corpus agreement plus compiled execution.

``mncs/fabric_lifecycle_status.mncs`` owns the pure status derivation in
``src/mncs_fabric/lifecycle.py`` (``_record_status`` and
``_request_status``): given already established boolean facts, which
authorization/request status holds. These tests prove the Python
authority and the MNCS module agree:

- the checked-in corpus expectations match the Python derivation over
  synthetic ledger shapes (always runs; guards corpus drift), and
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

from mncs_fabric.lifecycle import _record_status, _request_status

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_lifecycle_status.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_lifecycle_status_corpus.json"

AUTH_PY = {"Active": "ACTIVE", "Consumed": "CONSUMED", "Expired": "EXPIRED", "Revoked": "REVOKED"}
DECISION_PY = {"Approved": "APPROVED", "Denied": "DENIED", "Expired": "EXPIRED"}
AUTH_ID = "auth-corpus-1"
REQUEST_ID = "req-corpus-1"
NOW = "2029-06-01T00:00:00Z"
FUTURE_EXPIRY = "2030-01-01T00:00:00Z"
PAST_EXPIRY = "2028-01-01T00:00:00Z"


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


def _auth_records(expired_by_time: bool, revoked: bool, expired_event: bool, consumed: bool) -> list[dict]:
    records = [
        {
            "record_type": "enrollment.authorization",
            "record": {
                "authorization_id": AUTH_ID,
                "expires_at": PAST_EXPIRY if expired_by_time else FUTURE_EXPIRY,
            },
        }
    ]
    if consumed:
        records.append(
            {"record_type": "enrollment.authorization",
             "record": {"authorization_id": AUTH_ID, "event": "consumed"}}
        )
    if revoked:
        records.append(
            {"record_type": "enrollment.authorization",
             "record": {"authorization_id": AUTH_ID, "event": "revoked"}}
        )
    if expired_event:
        records.append(
            {"record_type": "enrollment.authorization",
             "record": {"authorization_id": AUTH_ID, "event": "expired"}}
        )
    return records


class TestLifecycleStatusCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertTrue(by_id)
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            if case["id"].startswith("auth-"):
                revoked, expired_event = _boolean(arguments[0]), _boolean(arguments[1])
                expired_by_time, consumed = _boolean(arguments[2]), _boolean(arguments[3])
                expected = _record_status(
                    _auth_records(expired_by_time, revoked, expired_event, consumed),
                    AUTH_ID,
                    NOW,
                )
                self.assertEqual(AUTH_PY[_finite_variant(case["expected"][0])], expected, case["id"])
            elif case["id"].startswith("request-"):
                has_decision = _boolean(arguments[0])
                decision = DECISION_PY[_finite_variant(arguments[1])]
                auth = AUTH_PY[_finite_variant(arguments[2])]
                # Rebuild the exact shape the generator used: Expired comes
                # from a past deadline, never from an expiry event here.
                records = _auth_records(
                    expired_by_time=auth == "EXPIRED",
                    revoked=auth == "REVOKED",
                    expired_event=False,
                    consumed=auth == "CONSUMED",
                )
                records.append(
                    {"record_type": "enrollment.request",
                     "record": {"request_id": REQUEST_ID, "authorization_id": AUTH_ID}}
                )
                if has_decision:
                    records.append(
                        {"record_type": "enrollment.decision",
                         "record": {"request_id": REQUEST_ID, "decision": decision}}
                    )
                expected = _request_status(records, REQUEST_ID, NOW)
                obtained = case["expected"][0]
                self.assertEqual(
                    {"Pending": "PENDING", "Approved": "APPROVED", "Denied": "DENIED", "Expired": "EXPIRED"}[
                        _finite_variant(obtained)
                    ],
                    expected,
                    case["id"],
                )
            else:
                self.fail(f"corpus case has an unexpected id shape: {case['id']}")

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.lifecycle_status;", text)
        self.assertIn("fn candidate_authorization(", text)
        self.assertIn("fn candidate_request(", text)

    def test_revocation_outranks_expiry(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        # Revoked plus every other flag still reports Revoked.
        self.assertEqual(_finite_variant(by_id["auth-rev1-exp1-time1-con1"]["expected"][0]), "Revoked")
        self.assertEqual(_finite_variant(by_id["auth-rev0-exp1-time1-con1"]["expected"][0]), "Expired")
        self.assertEqual(_finite_variant(by_id["auth-rev0-exp0-time0-con1"]["expected"][0]), "Consumed")
        self.assertEqual(_finite_variant(by_id["auth-rev0-exp0-time0-con0"]["expected"][0]), "Active")


class TestLifecycleStatusMncsExecution(unittest.TestCase):
    def test_toolchain_executes_lifecycle_status_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-lifecycle-status-") as tmp:
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
