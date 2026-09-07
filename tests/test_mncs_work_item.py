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

from mncs_fabric.work_queue import _TERMINAL

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_work_item.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_work_item_corpus.json"

HOLD_PY = {"Dispatch": "dispatch", "PausedHold": "paused", "NoEligibleHold": "noeligible"}


def _queue_key(priority: int, work_id: str) -> tuple[int, str]:
    # The exact sort key behind WorkQueue.tick (ascending priority).
    return (int(priority or 100), work_id)


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
                a_priority, b_priority = _integer(arguments[0]), _integer(arguments[1])
                if a_priority == b_priority:
                    # Strict comparator: a tie is false; the host-side
                    # work-id order decides.
                    self.assertFalse(case["expected"][0]["boolean"]["value"], case["id"])
                else:
                    first = "a" if _queue_key(a_priority, "a") < _queue_key(b_priority, "b") else "b"
                    self.assertEqual(
                        case["expected"][0]["boolean"]["value"], first == "a", case["id"])
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
        for entrypoint in ("fn candidate_terminal(", "fn candidate_priority(", "fn candidate_hold("):
            self.assertIn(entrypoint, text)

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
