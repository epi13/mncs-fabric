"""Fabric scheduler rank/admission relations in MNCS: agreement plus execution.

``mncs/fabric_scheduler_rank.mncs`` owns the pure numeric relations
behind fleet ranking and admission (``resolve_fleet`` sort key,
replica bounds, concurrency admission in ``scheduler.py``). The fleet
sort itself stays host-side (P-007); the comparator the sort consults
is MNCS-owned and pinned here, then executed.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "fabric_scheduler_rank.mncs"
CORPUS = REPO_ROOT / "mncs" / "fabric_scheduler_rank_corpus.json"


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


def _rank_key(pref_hits: int, constrained: bool) -> tuple[int, int]:
    # The exact sort key behind resolve_fleet (identity tie-break excluded).
    return (-pref_hits, 1 if constrained else 0)


class TestSchedulerRankCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            expected = case["expected"][0]["boolean"]["value"]
            if case["id"].startswith("rank-"):
                a_pref, a_con = _integer(arguments[0]), _boolean(arguments[1])
                b_pref, b_con = _integer(arguments[2]), _boolean(arguments[3])
                self.assertEqual(
                    expected, _rank_key(a_pref, a_con) < _rank_key(b_pref, b_con), case["id"])
            elif case["id"].startswith("replicas-"):
                eligible, replicas = _integer(arguments[0]), _integer(arguments[1])
                self.assertEqual(expected, eligible >= replicas, case["id"])
            elif case["id"].startswith("slot-"):
                active, limit = _integer(arguments[0]), _integer(arguments[1])
                self.assertEqual(expected, active < limit, case["id"])
            elif case["id"].startswith("valid-"):
                replicas = _integer(arguments[0])
                self.assertEqual(expected, 1 <= replicas <= 64, case["id"])
            else:
                self.fail(f"corpus case has an unexpected id shape: {case['id']}")

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.scheduler_rank;", text)
        for entrypoint in ("fn candidate_rank(", "fn candidate_replicas(",
                           "fn candidate_slot(", "fn candidate_replicas_valid("):
            self.assertIn(entrypoint, text)

    def test_full_tie_prefers_neither(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        # Identical workers: strict comparator is false both ways, so the
        # host-side identity tie-break decides deterministically.
        self.assertFalse(by_id["rank-2-0-2-0"]["expected"][0]["boolean"]["value"])
        self.assertFalse(by_id["rank-1-1-1-1"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["rank-2-0-1-0"]["expected"][0]["boolean"]["value"])
        # A constrained worker sorts after an otherwise identical
        # unconstrained one, never before it.
        self.assertFalse(by_id["rank-1-1-1-0"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["rank-1-0-1-1"]["expected"][0]["boolean"]["value"])


class TestSchedulerRankMncsExecution(unittest.TestCase):
    def test_toolchain_executes_scheduler_rank_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-scheduler-rank-") as tmp:
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
