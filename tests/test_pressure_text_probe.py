"""Pressure reproducer P-005/P-014: bounded byte-level text mechanics.

``development-pressure/reproducers/text_arch_probe.mncs`` proves what
today's language CAN do with text-like input (profile 0.7): exact-width
byte-token matching, ASCII digit accumulation, and reuse of the shared
``mncs.core.bytes.v1`` classifiers through imports. It equally pins
what it CANNOT do: variable-length platform strings (amd64, arm64,
riscv64, i386, ...) need views and cannot reach the fixed-width
entrypoints.

Agreement (always runs) checks the Python classifiers agree on every
covered token; execution (gated, needs the language library checkout)
runs the reproducer on research-bytecode, WASM, and C11.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.capability_resolution import classify_arch

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "development-pressure" / "reproducers" / "text_arch_probe.mncs"
CORPUS = REPO_ROOT / "development-pressure" / "reproducers" / "text_probe_corpus.json"

BACKENDS = ("research-bytecode", "mncs-portable-wasm-mvp", "mncs-c11")


def _find_language_cli() -> str | None:
    explicit = os.environ.get("MNCS_LANGUAGE_CLI")
    if explicit and Path(explicit).is_file():
        return explicit
    sibling = REPO_ROOT.parent / "mncs-language" / "target" / "debug" / "mncs"
    if sibling.is_file():
        return str(sibling)
    return None


def _language_library() -> Path | None:
    explicit = os.environ.get("MNCS_LANGUAGE_DIR")
    if explicit:
        candidate = Path(explicit) / "library"
    else:
        candidate = REPO_ROOT.parent / "mncs-language" / "library"
    return candidate if candidate.is_dir() else None


def _sequence_text(argument: dict) -> bytes:
    return bytes(item["byte"]["value"] for item in argument["sequence"]["values"])


class TestTextProbeAgreement(unittest.TestCase):
    def test_covered_tokens_agree_with_python_classifiers(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            arguments = case["request"]["arguments"]
            expected = case["expected"][0]
            if case["id"].startswith("x86-"):
                token = _sequence_text(arguments[0]).decode("ascii")
                self.assertEqual(expected["boolean"]["value"], token == "x86_64", case["id"])
                if token == token.lower():
                    self.assertEqual(classify_arch(token) == "x86_64", token == "x86_64", case["id"])
                else:
                    # Pinned split: the host classifier folds case, the
                    # byte-exact MNCS probe does not. Case normalization
                    # stays a host reduction until views land (P-014).
                    self.assertEqual(classify_arch(token), "x86_64", case["id"])
            elif case["id"].startswith("aarch64-"):
                token = _sequence_text(arguments[0]).decode("ascii")
                self.assertEqual(expected["boolean"]["value"], token == "aarch64", case["id"])
                if token == token.lower():
                    self.assertEqual(classify_arch(token) == "aarch64", token == "aarch64", case["id"])
                else:
                    self.assertEqual(classify_arch(token), "aarch64", case["id"])
            elif case["id"].startswith("digits-"):
                digits = bytes(a["byte"]["value"] for a in arguments)
                want = int(digits) if digits.isdigit() else -1
                self.assertEqual(expected["integer"]["value"], want, case["id"])
            else:
                self.fail(f"reproducer case has an unexpected id shape: {case['id']}")

    def test_variable_length_tokens_are_out_of_reach(self) -> None:
        # The pressure itself, pinned as a test: real platform strings no
        # fixed-width byte-exact entrypoint accepts, although the host
        # classifier resolves them. Widths 6/7 exist, but only for the two
        # exact contents; everything else needs views (P-014).
        cases = {"amd64": "x86_64", "arm64": "aarch64", "riscv64": "riscv64",
                 "i386": "x86", "x86": "x86"}
        for token, want in cases.items():
            with self.subTest(token=token):
                self.assertEqual(classify_arch(token), want)
                matched = token in ("x86_64", "aarch64")
                self.assertFalse(matched, token)


class TestTextProbeExecution(unittest.TestCase):
    def test_reproducer_executes_on_available_backends(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        library = _language_library()
        if library is None:
            self.skipTest("mncs-language library checkout is unavailable (set MNCS_LANGUAGE_DIR)")
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="fabric-pressure-text-") as tmp:
            env = dict(os.environ, MNCS_LIBRARY_PATH=str(library))
            for backend in BACKENDS:
                with self.subTest(backend=backend):
                    completed = subprocess.run(
                        [cli, "experiment", "run", str(SOURCE), "--backend", backend,
                         "--corpus", str(CORPUS), "--output-dir", str(Path(tmp) / backend)],
                        capture_output=True, text=True, timeout=3600, env=env,
                    )
                    self.assertEqual(completed.returncode, 0,
                                     f"{backend} run failed: {completed.stderr[-2000:]}")
                    result = json.loads(completed.stdout)
                    for judgement in result.get("translation_validations", []):
                        self.assertEqual(judgement.get("judgement"), "PASS", judgement)
                    cases = result.get("cases", [])
                    self.assertEqual(len(cases), len(corpus["cases"]))
                    failures = [item.get("case_id") for item in cases
                                if item.get("status") != "returned" or not item.get("expectation_met")]
                    self.assertEqual(failures, [], f"{backend} disagrees: {failures}")


if __name__ == "__main__":
    unittest.main()
