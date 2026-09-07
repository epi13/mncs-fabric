"""Fabric management-state machine in MNCS: corpus agreement plus compiled execution.

``mncs/fabric_management.mncs`` owns the controller management-state
transition relation, the scheduling gate, and the READY/certification
invariant (the strict tables in ``src/mncs_fabric/management.py``). These
tests prove the Python mirror agrees with it:

- the checked-in corpus expectations match the Python authority tables
  (always runs; guards corpus drift), and
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

from mncs_fabric.management import _TRANSITIONS, management_allows_work

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_management.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_management_corpus.json"
MODULE = "fabric.management"

STATES = ["READY", "BUSY", "DRAINING", "MAINTENANCE", "VERIFYING", "DEGRADED", "QUARANTINED"]


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


class TestManagementCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        for source in STATES:
            for target in STATES:
                case = by_id[f"transition-{source}-{target}"]
                expected = _finite_variant(case["expected"][0])
                # Strict table: the MNCS module owns the table without the
                # host-side reflexive closure in `can_transition`.
                allowed = target in _TRANSITIONS[source]
                self.assertEqual(expected, "ALLOWED" if allowed else "DENIED", case["id"])
        for state in STATES:
            case = by_id[f"allows-work-{state}"]
            self.assertEqual(
                case["expected"][0]["boolean"]["value"],
                management_allows_work(state),
                case["id"],
            )
        for state in STATES:
            for failed in (False, True):
                case = by_id[f"certification-{state}-failed-{int(failed)}"]
                # Python authority: READY with FAILED certification is
                # rejected in build_management_state; nothing else is gated.
                self.assertEqual(
                    case["expected"][0]["boolean"]["value"],
                    not (state == "READY" and failed),
                    case["id"],
                )

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.management;", text)
        for entrypoint in (
            "fn candidate(",
            "fn candidate_allows_work(",
            "fn candidate_certification(",
        ):
            self.assertIn(entrypoint, text)

    def test_schedulable_states_are_pinned(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertTrue(by_id["allows-work-READY"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["allows-work-BUSY"]["expected"][0]["boolean"]["value"])
        for state in ("DRAINING", "MAINTENANCE", "VERIFYING", "DEGRADED", "QUARANTINED"):
            self.assertFalse(by_id[f"allows-work-{state}"]["expected"][0]["boolean"]["value"])
        # A worker that failed certification never presents as READY.
        self.assertFalse(by_id["certification-READY-failed-1"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["certification-READY-failed-0"]["expected"][0]["boolean"]["value"])


class TestManagementMncsExecution(unittest.TestCase):
    def test_toolchain_executes_management_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-management-") as tmp:
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
