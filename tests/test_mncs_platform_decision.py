"""Fabric platform decisions pinned to the shared MNCS standard library.

Fabric does not keep its own copy of the platform vocabulary:
``mncs.std.platform.v1`` (in mncs-language ``library/std/platform.mncs``)
owns the finite platform decision (OS/arch/libc/CUDA/resources/flags
plus the composed environment check), and Section 1 of
``src/mncs_fabric/capability_resolution.py`` mirrors it. These tests
prove the Python mirror agrees with the standard library:

- the checked-in corpus expectations match the Python authority functions
  (always runs; guards corpus drift), and
- the MNCS toolchain executes the standard library file itself over the
  whole corpus and its judgement is PASS (runs when the language
  checkout and CLI are available; the CI ``mncs-conformance`` job builds
  them at a pinned revision).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.capability_resolution import (
    arch_matches,
    arch_satisfies,
    cuda_satisfies,
    env_satisfies,
    flag_satisfies,
    libc_satisfies,
    os_satisfies,
    resources_satisfy,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "mncs" / "std_platform_parity_corpus.json"
MODULE = "mncs.std.platform.v1"


def _language_dir() -> Path:
    explicit = os.environ.get("MNCS_LANGUAGE_DIR")
    if explicit:
        return Path(explicit)
    return REPO_ROOT.parent / "mncs-language"


def _platform_source() -> Path:
    return _language_dir() / "library" / "std" / "platform.mncs"


SOURCE = _platform_source()

OS_MNCS = ["Linux", "Windows", "MacOs", "Unknown"]
OS_PY = ["linux", "windows", "macos", "unknown"]
REQ_OS_MNCS = ["Any", "Linux", "Windows", "MacOs"]
REQ_OS_PY = ["any", "linux", "windows", "macos"]
ARCH_MNCS = ["X86_64", "Aarch64", "Riscv64", "X86", "Arm32", "Unknown"]
ARCH_PY = ["x86_64", "aarch64", "riscv64", "x86", "arm32", "unknown"]
REQ_ARCH_MNCS = ["Any", "X86_64", "Aarch64", "Riscv64", "X86", "Arm32"]
REQ_ARCH_PY = ["any", "x86_64", "aarch64", "riscv64", "x86", "arm32"]
LIBC_MNCS = ["Gnu", "Musl", "WasiC", "WinCrt", "Unknown"]
LIBC_PY = ["gnu", "musl", "wasi-c", "win-crt", "unknown"]
REQ_LIBC_MNCS = ["Any", "Gnu", "Musl", "WasiC", "WinCrt"]
REQ_LIBC_PY = ["any", "gnu", "musl", "wasi-c", "win-crt"]
ACCEL_MNCS = ["None", "Cuda", "Rocm", "Metal", "Unknown"]
ACCEL_PY = ["none", "cuda", "rocm", "metal", "unknown"]
EXEC_MNCS = ["Native", "Emulated"]
EXEC_PY = ["native", "emulated"]


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


def _record_fields(argument: dict) -> dict[str, object]:
    return {name: value for name, value in argument["record"]["fields"]}


class TestPlatformDecisionCorpusAgreement(unittest.TestCase):
    def test_corpus_expectations_match_python_authority(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertTrue(by_id)
        for case in corpus["cases"]:
            case_id = case["id"]
            expected = case["expected"][0]["boolean"]["value"]
            if case_id.startswith("os-"):
                _, req, got = case_id.split("-")
                self.assertEqual(
                    expected,
                    os_satisfies(REQ_OS_PY[REQ_OS_MNCS.index(req)], OS_PY[OS_MNCS.index(got)]),
                    case_id,
                )
            elif case_id.startswith("arch-match-"):
                _, _, req, got = case_id.split("-")
                self.assertEqual(
                    expected,
                    arch_matches(REQ_ARCH_PY[REQ_ARCH_MNCS.index(req)], ARCH_PY[ARCH_MNCS.index(got)]),
                    case_id,
                )
            elif case_id.startswith("arch-"):
                parts = case_id.split("-")
                req, got = parts[1], parts[2]
                allow = bool(int(parts[3].removeprefix("allow")))
                emulates = bool(int(parts[4].removeprefix("emul")))
                exec_mode = parts[5]
                arguments = case["request"]["arguments"]
                # Cross-check the boolean/enum arguments decode as encoded.
                self.assertEqual(_boolean(arguments[2]), allow, case_id)
                self.assertEqual(_boolean(arguments[3]), emulates, case_id)
                self.assertEqual(
                    expected,
                    arch_satisfies(
                        REQ_ARCH_PY[REQ_ARCH_MNCS.index(req)],
                        ARCH_PY[ARCH_MNCS.index(got)],
                        allow_emulation=allow,
                        emulates_req_arch=emulates,
                        exec_mode=EXEC_PY[EXEC_MNCS.index(exec_mode)],
                    ),
                    case_id,
                )
            elif case_id.startswith("libc-"):
                _, req, got = case_id.split("-")
                self.assertEqual(
                    expected,
                    libc_satisfies(REQ_LIBC_PY[REQ_LIBC_MNCS.index(req)], LIBC_PY[LIBC_MNCS.index(got)]),
                    case_id,
                )
            elif case_id.startswith("cuda-"):
                parts = case_id.split("-")
                require = bool(int(parts[1].removeprefix("req")))
                req_major, req_minor = int(parts[2]), int(parts[3])
                got, got_major, got_minor = parts[4], int(parts[5]), int(parts[6])
                self.assertEqual(
                    expected,
                    cuda_satisfies(
                        require, req_major, req_minor,
                        ACCEL_PY[ACCEL_MNCS.index(got)], got_major, got_minor,
                    ),
                    case_id,
                )
            elif case_id.startswith("resources-"):
                _, min_mem, min_cpu, got_mem, got_cpu = case_id.split("-")
                self.assertEqual(
                    expected,
                    resources_satisfy(int(min_mem), int(min_cpu), int(got_mem), int(got_cpu)),
                    case_id,
                )
            elif case_id.startswith("flag-"):
                parts = case_id.split("-")
                require = bool(int(parts[1].removeprefix("req")))
                got = bool(int(parts[2].removeprefix("got")))
                self.assertEqual(expected, flag_satisfies(require, got), case_id)
            elif case_id.startswith("env-"):
                arguments = case["request"]["arguments"]
                req_fields = _record_fields(arguments[0])
                env_fields = _record_fields(arguments[1])
                req = {
                    "os": REQ_OS_PY[REQ_OS_MNCS.index(_finite_variant(req_fields["os"]))],
                    "arch": REQ_ARCH_PY[REQ_ARCH_MNCS.index(_finite_variant(req_fields["arch"]))],
                    "libc": REQ_LIBC_PY[REQ_LIBC_MNCS.index(_finite_variant(req_fields["libc"]))],
                    "require_cuda": _boolean(req_fields["require_cuda"]),
                    "cuda_major": _integer(req_fields["cuda_major"]),
                    "cuda_minor": _integer(req_fields["cuda_minor"]),
                    "require_ebpf": _boolean(req_fields["require_ebpf"]),
                    "require_wasm": _boolean(req_fields["require_wasm"]),
                    "require_ptx": _boolean(req_fields["require_ptx"]),
                    "allow_emulation": _boolean(req_fields["allow_emulation"]),
                    "min_mem_mib": _integer(req_fields["min_mem_mib"]),
                    "min_cpu_count": _integer(req_fields["min_cpu_count"]),
                }
                env = {
                    "os": OS_PY[OS_MNCS.index(_finite_variant(env_fields["os"]))],
                    "arch": ARCH_PY[ARCH_MNCS.index(_finite_variant(env_fields["arch"]))],
                    "libc": LIBC_PY[LIBC_MNCS.index(_finite_variant(env_fields["libc"]))],
                    "accel": ACCEL_PY[ACCEL_MNCS.index(_finite_variant(env_fields["accel"]))],
                    "exec_mode": EXEC_PY[EXEC_MNCS.index(_finite_variant(env_fields["exec"]))],
                    "cuda_major": _integer(env_fields["cuda_major"]),
                    "cuda_minor": _integer(env_fields["cuda_minor"]),
                    "has_ebpf": _boolean(env_fields["has_ebpf"]),
                    "has_wasm": _boolean(env_fields["has_wasm"]),
                    "has_ptx": _boolean(env_fields["has_ptx"]),
                    "mem_mib": _integer(env_fields["mem_mib"]),
                    "cpu_count": _integer(env_fields["cpu_count"]),
                    "emulates_req_arch": _boolean(env_fields["emulates_req_arch"]),
                }
                self.assertEqual(expected, env_satisfies(req, env), case_id)
            else:
                self.fail(f"corpus case has an unexpected id shape: {case_id}")

    def test_source_declares_the_executed_module(self) -> None:
        if not SOURCE.is_file():
            self.skipTest(f"mncs-language checkout is unavailable at {SOURCE}")
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("module mncs.std.platform.v1;", text)
        for entrypoint in (
            "fn candidate_os(",
            "fn arch_matches(",
            "fn candidate_arch(",
            "fn candidate_libc(",
            "fn candidate_cuda(",
            "fn candidate_resources(",
            "fn candidate_flag(",
            "fn candidate_env(",
        ):
            self.assertIn(entrypoint, text)

    def test_unknown_observations_satisfy_nothing(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        self.assertFalse(by_id["os-Linux-Unknown"]["expected"][0]["boolean"]["value"])
        self.assertFalse(by_id["libc-Gnu-Unknown"]["expected"][0]["boolean"]["value"])
        self.assertTrue(by_id["os-Any-Unknown"]["expected"][0]["boolean"]["value"])

    def test_init_fact_is_ignored_by_composition(self) -> None:
        # The worker environment carries init on both sides; the composed
        # check must agree under either value. The corpus runs every env
        # scenario twice (init Unknown vs Systemd).
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        by_id = {case["id"]: case for case in corpus["cases"]}
        bases = sorted({case_id.removeprefix("env-").rsplit("-init-", 1)[0]
                        for case_id in by_id if case_id.startswith("env-")})
        self.assertTrue(bases)
        for base in bases:
            unknown = by_id[f"env-{base}-init-unknown"]["expected"][0]["boolean"]["value"]
            systemd = by_id[f"env-{base}-init-systemd"]["expected"][0]["boolean"]["value"]
            self.assertEqual(unknown, systemd, base)


class TestPlatformDecisionMncsExecution(unittest.TestCase):
    def test_toolchain_executes_platform_corpus(self) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            self.skipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        if not SOURCE.is_file():
            self.skipTest(f"mncs-language checkout is unavailable at {SOURCE}")
        cli = _find_language_cli()
        if cli is None:
            self.skipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-platform-") as tmp:
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
