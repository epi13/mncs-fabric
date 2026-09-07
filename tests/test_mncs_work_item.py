"""Fabric scheduled-work item decisions in MNCS: agreement plus execution.

``mncs/fabric_work_item.mncs`` owns the pure per-item relations from
``src/mncs_fabric/work_queue.py`` (terminal classification, priority
order, dispatch holds). Ledgers, clocks, idempotency, and dispatch
effects stay host-side; the decisions the tick consults are MNCS-owned
and pinned here, then executed.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.errors import ValidationError
from mncs_fabric.work_queue import _TERMINAL, checked_priority

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_work_item.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_work_item_corpus.json"

HOLD_PY = {"Dispatch": "dispatch", "PausedHold": "paused", "NoEligibleHold": "noeligible"}


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


def _integer(argument: dict) -> int:
    return int(argument["integer"]["value"])


class TestWorkItemCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            if case["id"].startswith("terminal-"):
                state = case["id"].removeprefix("terminal-")
                # The OTHER case exercises the NonTerminal folding arm.
                self.assertEqual(
                    case["expected"][0]["boolean"]["value"], state in _TERMINAL, case["id"])
            elif case["id"].startswith("priority-"):
                # Arguments arrive pre-folded to effective priorities (the
                # fold itself is pinned by the effective-* cases); the
                # strict comparator answers, ties going to the host-side
                # work-id order.
                a_priority, b_priority = _integer(arguments[0]), _integer(arguments[1])
                self.assertEqual(
                    case["expected"][0]["boolean"]["value"], a_priority < b_priority, case["id"])
            elif case["id"].startswith("effective-"):
                raw = _integer(arguments[0])
                self.assertEqual(
                    case["expected"][0]["integer"]["value"], 100 if raw == 0 else raw, case["id"])
            elif case["id"].startswith("hold-"):
                paused, eligible = _boolean(arguments[0]), _boolean(arguments[1])
                # The exact hold order behind WorkQueue.tick: an operator
                # pause outranks missing eligibility.
                if paused:
                    hold = "paused"
                elif eligible:
                    hold = "dispatch"
                else:
                    hold = "noeligible"
                self.assertEqual(
                    HOLD_PY[_finite_variant(case["expected"][0])], hold, case["id"])
            else:
                self.fail(f"corpus case has an unexpected id shape: {case['id']}")

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.work_item;", text)
        for entrypoint in ("fn candidate_terminal(", "fn candidate_priority(",
                           "fn candidate_hold(", "fn candidate_effective("):
            self.assertIn(entrypoint, text)


class TestPriorityContract(unittest.TestCase):
    """The clarified i64 priority domain (review: no silent narrowing)."""

    def test_falsy_inputs_store_the_default(self) -> None:
        for raw in (None, 0, "", False):
            self.assertEqual(checked_priority(raw), 100, repr(raw))

    def test_legal_values_pass_through(self) -> None:
        self.assertEqual(checked_priority(1), 1)
        self.assertEqual(checked_priority(-5), -5)
        self.assertEqual(checked_priority("50"), 50)
        self.assertEqual(checked_priority(2**31), 2**31)
        self.assertEqual(checked_priority(2**63 - 1), 2**63 - 1)
        self.assertEqual(checked_priority(-(2**63)), -(2**63))

    def test_out_of_range_rejected(self) -> None:
        for raw in (2**63, -(2**63) - 1, 10**30):
            with self.assertRaises(ValidationError, msg=repr(raw)):
                checked_priority(raw)

    def test_garbage_rejected_as_validation_error(self) -> None:
        for raw in ("abc", "3.5x", [1], {"p": 1}):
            with self.assertRaises(ValidationError, msg=repr(raw)):
                checked_priority(raw)

    def test_terminal_set_is_pinned(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        for state in ("COMPLETED", "FAILED", "CANCELLED"):
            self.assertTrue(by_id[f"terminal-{state}"]["expected"][0]["boolean"]["value"])
        for state in ("QUEUED", "DISPATCHED", "OTHER"):
            self.assertFalse(by_id[f"terminal-{state}"]["expected"][0]["boolean"]["value"])


class TestWorkItemMncsExecution(unittest.TestCase):
    def test_toolchain_executes_work_item_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-work-item-") as tmp:
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
