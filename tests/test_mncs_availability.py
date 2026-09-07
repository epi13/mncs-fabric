"""Fabric availability-window decision in MNCS: agreement plus execution.

``mncs/fabric_availability.mncs`` owns the pure window relation from
``src/mncs_fabric/availability.py::window_contains``: the host reduces
clocks/timezones/day-sets to normalized minutes plus a day-membership
bit, and MNCS decides openness (including the always-open empty window
and midnight wrap). Tests prove Python and MNCS agree, then execute.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import time
from pathlib import Path

from mncs_fabric.availability import window_contains

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_availability.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_availability_corpus.json"


def _find_language_cli() -> str | None:
    explicit = os.environ.get("MNCS_LANGUAGE_CLI")
    if explicit and Path(explicit).is_file():
        return explicit
    sibling = REPO_ROOT.parent / "mncs-language" / "target" / "debug" / "mncs"
    if sibling.is_file():
        return str(sibling)
    return None


def _boolean(argument: dict) -> bool:
    return bool(argument["boolean"]["value"])


def _integer(argument: dict) -> int:
    return int(argument["integer"]["value"])


def _clock(minutes: int) -> time:
    return time(minutes // 60 % 24, minutes % 60)


class TestAvailabilityCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            day_in, begin, finish, now = (
                _boolean(arguments[0]), _integer(arguments[1]),
                _integer(arguments[2]), _integer(arguments[3]),
            )
            expected = day_in and window_contains(_clock(begin), _clock(finish), _clock(now))
            self.assertEqual(case["expected"][0]["boolean"]["value"], expected, case["id"])

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.availability;", text)
        self.assertIn("fn candidate(", text)

    def test_midnight_wrap_and_empty_window_are_pinned(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        # Empty window is always open when the day matches.
        self.assertTrue(by_id["window-day1-720-720-720"]["expected"][0]["boolean"]["value"])
        self.assertFalse(by_id["window-day0-720-720-720"]["expected"][0]["boolean"]["value"])
        # Wrap window 23:00-01:00 holds at midnight, releases just past
        # the (exclusive) 01:00 close.
        self.assertTrue(by_id["window-day1-1380-60-0"]["expected"][0]["boolean"]["value"])
        self.assertFalse(by_id["window-day1-1380-60-61"]["expected"][0]["boolean"]["value"])


class TestAvailabilityMncsExecution(unittest.TestCase):
    def test_toolchain_executes_availability_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-availability-") as tmp:
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
