"""Fabric update policy in MNCS: corpus agreement plus compiled execution.

``mncs/update_lifecycle.mncs`` reconstructs the Python update-state
transition relation and version precedence as language-owned source.
These tests prove the two implementations agree:

- the checked-in corpus expectations match the Python authority tables
  (always runs; guards corpus drift), and
- the MNCS toolchain executes the module over the whole corpus and its
  judgement is PASS (runs when the language CLI is available; the CI
  ``mncs-conformance`` job builds it at a pinned revision).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.update_lifecycle import UPDATE_STATES, _TRANSITIONS
from mncs_fabric.versioning import parse_fabric_version

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "update_lifecycle.mncs"
CORPUS = REPO_ROOT / "mncs" / "update_lifecycle_corpus.json"
MODULE = "fabric.update_lifecycle"


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


class TestUpdatePolicyCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        for source in UPDATE_STATES:
            for target in UPDATE_STATES:
                case = by_id[f"transition-{source}-{target}"]
                expected = _finite_variant(case["expected"][0])
                allowed = target in _TRANSITIONS[source]
                self.assertEqual(expected, "ALLOWED" if allowed else "DENIED", case["id"])
        version_cases = [item for item in corpus["cases"] if item["id"].startswith("version-")]
        self.assertTrue(version_cases)
        for item in version_cases:
            _, left, _, right = item["id"].split("-", 3)
            left_tuple = parse_fabric_version(left)
            right_tuple = parse_fabric_version(right)
            assert left_tuple is not None and right_tuple is not None
            expected = list(left_tuple.as_tuple()) < list(right_tuple.as_tuple())
            self.assertEqual(item["expected"][0]["boolean"]["value"], expected, item["id"])

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.update_lifecycle;", text)
        self.assertIn("fn candidate(", text)
        self.assertIn("fn version_candidate(", text)


class TestUpdatePolicyMncsExecution(unittest.TestCase):
    def test_toolchain_executes_policy_corpus(self) -> None:
        # Full-corpus execution is minutes-long by toolchain design (see
        # docs/MNCS_UPDATE_POLICY.md pressure notes). It runs in the
        # dedicated mncs-conformance workflow, not in the default suite.
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-conformance-") as tmp:
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
                # Full finite-domain execution is minutes-long by toolchain
                # design (see docs/MNCS_UPDATE_POLICY.md pressure notes):
                # ~9 min CPU locally, over 20 min on a hosted runner.
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
