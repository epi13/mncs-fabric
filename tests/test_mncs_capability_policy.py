"""Fabric capability resolution in MNCS: corpus agreement plus compiled execution.

``mncs/worker_capability.mncs`` owns the pre-execution eligibility
relation (provenance trust, freshness lattice, intent/policy
compatibility, ordered resolution codes). These tests prove the Python
mirror agrees with it:

- the checked-in corpus expectations match the Python authority
  functions (always runs; guards corpus drift), and
- the MNCS toolchain executes the module over the whole corpus and its
  judgement is PASS (runs when the language CLI is available; the CI
  ``mncs-conformance`` job builds it at a pinned revision).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.capability_resolution import (
    freshness_of,
    intent_allowed,
    is_eligible,
    provenance_trusted,
    resolve_code,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "worker_capability.mncs"
CORPUS = REPO_ROOT / "mncs" / "worker_capability_corpus.json"
MODULE = "fabric.worker_capability"

LIVENESS_MNCS = {"Available": "AVAILABLE", "Unavailable": "UNAVAILABLE", "Disconnected": "DISCONNECTED"}
FRESHNESS_MNCS = {"Fresh": "fresh", "Stale": "stale"}
PROVENANCE_MNCS = {
    "WorkerObserved": "worker-observed",
    "OperatorAsserted": "operator-asserted",
    "ConsumerDeclared": "consumer-declared",
}
INTENT_MNCS = {"Normal": "normal", "Mutating": "mutating", "Privileged": "privileged"}
CODE_MNCS = {
    "Eligible": "ELIGIBLE",
    "CapabilityUnsatisfied": "CAPABILITY_UNSATISFIED",
    "PolicyDenied": "POLICY_DENIED",
    "ProvenanceUnverified": "PROVENANCE_UNVERIFIED",
    "WorkerStale": "WORKER_STALE",
    "WorkerUnavailable": "WORKER_UNAVAILABLE",
    "WorkerDisconnected": "WORKER_DISCONNECTED",
}
POLICY_FIELDS = (
    "experimental",
    "disposable",
    "allow_root_mutation",
    "allow_reboot",
    "allow_toolchain_install",
    "resource_constrained",
)


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


def _record_fields(argument: dict) -> dict[str, object]:
    return {name: value for name, value in argument["record"]["fields"]}


class TestCapabilityCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertTrue(by_id)
        for name, expected in PROVENANCE_MNCS.items():
            case = by_id[f"provenance-{name.lower()}"]
            self.assertEqual(
                case["expected"][0]["boolean"]["value"],
                provenance_trusted(expected),
                case["id"],
            )
        for case in corpus["cases"]:
            if not case["id"].startswith("freshness-age-"):
                continue
            age = int(case["id"].split("freshness-age-", 1)[1])
            expected = "Fresh" if freshness_of(float(age), 300.0) == "fresh" else "Stale"
            self.assertEqual(_finite_variant(case["expected"][0]), expected, case["id"])
        for case in corpus["cases"]:
            if not case["id"].startswith("intent-"):
                continue
            policy_name, intent = case["id"].split("intent-", 1)[1].rsplit("-", 1)
            arguments = case["request"]["arguments"]
            fields = _record_fields(arguments[0])
            # Record fields carry {"boolean": {"value": ...}} shapes.
            policy = {
                key: fields[key]["boolean"]["value"] for key in POLICY_FIELDS
            }
            self.assertEqual(
                case["expected"][0]["boolean"]["value"],
                intent_allowed(policy, INTENT_MNCS[intent.capitalize()]),
                case["id"],
            )
        for case in corpus["cases"]:
            if not case["id"].startswith("resolve-"):
                continue
            arguments = case["request"]["arguments"]
            live = next(key for key, value in LIVENESS_MNCS.items() if _finite_variant(arguments[0]) == key)
            fresh = next(key for key, value in FRESHNESS_MNCS.items() if _finite_variant(arguments[1]) == key)
            expected = resolve_code(
                liveness=LIVENESS_MNCS[live],
                freshness=FRESHNESS_MNCS[fresh],
                provenance_ok=_boolean(arguments[2]),
                env_ok=_boolean(arguments[3]),
                intent_ok=_boolean(arguments[4]),
            )
            expected_mncs = next(key for key, value in CODE_MNCS.items() if value == expected)
            self.assertEqual(_finite_variant(case["expected"][0]), expected_mncs, case["id"])
        for case in corpus["cases"]:
            if not case["id"].startswith("eligible-"):
                continue
            key = next(name for name in CODE_MNCS if case["id"] == f"eligible-{name.lower()}")
            self.assertEqual(
                case["expected"][0]["boolean"]["value"],
                is_eligible(CODE_MNCS[key]),
                case["id"],
            )

    def test_source_declares_the_executed_module(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module fabric.worker_capability;", text)
        for entrypoint in (
            "fn candidate_provenance(",
            "fn candidate_freshness(",
            "fn candidate_intent(",
            "fn candidate_resolve(",
            "fn candidate_eligible(",
        ):
            self.assertIn(entrypoint, text)

    def test_resolution_ordering_arms_are_pinned(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        # Reachability decides before freshness: the liveness match is the
        # outermost stage of resolve.
        resolve = text[text.index("fn resolve("): text.index("fn decide_fresh(")]
        self.assertLess(resolve.index("Unavailable"), resolve.index("Stale"))
        # Freshness before provenance before environment before policy: the
        # nesting of decide_fresh proves it — provenance_ok is the
        # outermost if, env_ok nested inside, intent_ok innermost.
        fresh = text[text.index("fn decide_fresh("): text.index("fn is_eligible(")]
        self.assertLess(fresh.index("if provenance_ok"), fresh.index("if env_ok"))
        self.assertLess(fresh.index("if env_ok"), fresh.index("if intent_ok"))
        self.assertIn("ResolutionCode.ProvenanceUnverified", fresh)
        self.assertIn("ResolutionCode.CapabilityUnsatisfied", fresh)
        self.assertIn("ResolutionCode.PolicyDenied", fresh)
        self.assertIn("ResolutionCode.Eligible", fresh)
        # Experimental status alone grants nothing: the bare-experimental
        # arm must still deny privileged work (pinned in the corpus too).
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertFalse(by_id["intent-experimental-bare-privileged"]["expected"][0]["boolean"]["value"])
        self.assertFalse(by_id["intent-stable-mutating"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["intent-stable-normal"]["expected"][0]["boolean"]["value"])
        # Consumer-declared observations never prove capability.
        self.assertFalse(by_id["provenance-consumerdeclared"]["expected"][0]["boolean"]["value"])


class TestCapabilityMncsExecution(unittest.TestCase):
    def test_toolchain_executes_resolution_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-capability-") as tmp:
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
