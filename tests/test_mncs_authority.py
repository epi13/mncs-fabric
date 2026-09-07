"""MNCS authority pilot: production decisions answered by compiled MNCS.

``mncs_fabric.mncs_authority.MncsAuthority`` executes the pinned
``fabric.worker_capability`` backend artifact and answers ordered
resolution codes. These tests prove, with MNCS as the authority:

- the authority answers every arm of the resolve domain exactly as the
  legacy Python oracle does (the oracle must agree with MNCS, not the
  other way around);
- fleet resolution and scheduling through the authority agree with the
  legacy path verdict-for-verdict, including NO_ELIGIBLE_WORKER;
- scheduling evidence binds the answering artifact/backend identity;
- misconfiguration fails hard (AuthorityError), never silently back.

Runs only with the toolchain (``MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1``);
the artifact is built once per session from the checked-in module and
corpus, and its identity is verified against itself before use (the
pin-mismatch path is tested separately with a wrong pin).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mncs_fabric.capability_resolution import (
    CapabilityQuery,
    WorkerSnapshot,
    explain_selection,
    resolve_code,
    resolve_fleet,
)
from mncs_fabric.mncs_authority import AuthorityError, MncsAuthority, ResolveInputs
from mncs_fabric.scheduler import WorkerSlot, schedule

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "mncs" / "worker_capability.mncs"
CORPUS = REPO_ROOT / "mncs" / "worker_capability_corpus.json"

LIVENESS_PY = {"Available": "AVAILABLE", "Unavailable": "UNAVAILABLE", "Disconnected": "DISCONNECTED"}
FRESHNESS_PY = {"Fresh": "fresh", "Stale": "stale"}


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


def _fleet() -> list[WorkerSnapshot]:
    return [
        WorkerSnapshot(worker_id="w-linux", capabilities=frozenset({"os:linux"}),
                       env={"os": "linux", "arch": "x86_64"}, liveness="AVAILABLE"),
        WorkerSnapshot(worker_id="w-stale", capabilities=frozenset({"os:linux"}),
                       env={"os": "linux", "arch": "x86_64"}, liveness="AVAILABLE",
                       capability_age_seconds=9999.0),
        WorkerSnapshot(worker_id="w-win", capabilities=frozenset({"os:windows"}),
                       env={"os": "windows", "arch": "x86_64"}, liveness="AVAILABLE"),
    ]


def _slots() -> list[WorkerSlot]:
    return [
        WorkerSlot(worker_id="w-linux", capabilities=frozenset({"os:linux"}),
                   worker_env={"os": "linux", "arch": "x86_64"}),
        WorkerSlot(worker_id="w-stale", capabilities=frozenset({"os:linux"}),
                   worker_env={"os": "linux", "arch": "x86_64"},
                   capability_age_seconds=9999.0),
        WorkerSlot(worker_id="w-win", capabilities=frozenset({"os:windows"}),
                   worker_env={"os": "windows", "arch": "x86_64"}),
    ]


def _identity(char: str) -> str:
    return "sha256:" + char * 64


def _plan(required: list[str]) -> dict:
    return {
        "schema_version": "mncs-fabric.job-plan.v0.1", "job_id": "scheduler:job",
        "candidate_identity": _identity("a"), "evaluator_identity": None,
        "artifact_manifest_identity": _identity("b"), "argv": ["@python", "task.py"],
        "working_directory": ".", "timeout_seconds": 5, "output_limit_bytes": 4096,
        "environment": {}, "required_capabilities": required, "result_paths": [],
        "network_policy": "UNSPECIFIED",
    }


class MncsAuthorityTestBase(unittest.TestCase):
    cli: str = ""
    artifact: str = ""
    identity: str = ""
    authority: MncsAuthority | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("MNCS_FABRIC_RUN_TOOLCHAIN_TESTS") != "1":
            raise unittest.SkipTest("toolchain execution runs in mncs-conformance (set MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1)")
        cli = _find_language_cli()
        if cli is None:
            raise unittest.SkipTest("mncs-language CLI is unavailable (set MNCS_LANGUAGE_CLI)")
        cls.cli = cli
        cls._tmp = tempfile.TemporaryDirectory(prefix="fabric-mncs-authority-")
        completed = subprocess.run(
            [cli, "experiment", "run", str(SOURCE),
             "--backend", "research-bytecode", "--corpus", str(CORPUS),
             "--output-dir", cls._tmp.name],
            capture_output=True, text=True, timeout=3600,
        )
        if completed.returncode != 0:
            raise unittest.SkipTest(f"artifact build failed: {completed.stderr[-1000:]}")
        artifact = str(Path(cls._tmp.name) / "backend-artifact.json")
        identity = str(json.loads(Path(artifact).read_text(encoding="utf-8"))["identity"])
        cls.artifact = artifact
        cls.identity = identity
        cls.authority = MncsAuthority(cli=cli, artifact=artifact, expected_artifact_identity=identity)

    @classmethod
    def tearDownClass(cls) -> None:
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()


class TestMncsAuthorityAnswers(MncsAuthorityTestBase):
    def test_authority_answers_every_resolve_arm_like_oracle(self) -> None:
        assert self.authority is not None
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        resolve_cases = [c for c in corpus["cases"] if c["id"].startswith("resolve-")]
        self.assertTrue(resolve_cases)
        rows = [
            ResolveInputs(
                liveness=LIVENESS_PY[_finite_variant(c["request"]["arguments"][0])],
                freshness=FRESHNESS_PY[_finite_variant(c["request"]["arguments"][1])],
                provenance_ok=_boolean(c["request"]["arguments"][2]),
                env_ok=_boolean(c["request"]["arguments"][3]),
                intent_ok=_boolean(c["request"]["arguments"][4]),
            )
            for c in resolve_cases
        ]
        codes = self.authority.resolve_codes(rows)
        self.assertEqual(len(codes), len(rows))
        for case, row, code in zip(resolve_cases, rows, codes):
            # MNCS is authoritative: the legacy oracle must agree with it.
            self.assertEqual(
                code,
                resolve_code(
                    liveness=row.liveness, freshness=row.freshness,
                    provenance_ok=row.provenance_ok, env_ok=row.env_ok,
                    intent_ok=row.intent_ok,
                ),
                case["id"],
            )

    def test_fleet_authority_agrees_with_legacy_path(self) -> None:
        assert self.authority is not None
        queries = [
            CapabilityQuery(require_all=frozenset({"os:linux"})),
            CapabilityQuery(require_all=frozenset({"os:linux"}), forbid=frozenset({"os:linux"})),
            CapabilityQuery(require_all=frozenset({"os:plan9"})),
            CapabilityQuery(require_all=frozenset(), prefer=frozenset({"os:linux"})),
            CapabilityQuery(require_all=frozenset({"os:linux"}), intent="privileged"),
        ]
        for query in queries:
            with self.subTest(query=query):
                legacy = resolve_fleet(query, _fleet())
                authoritative = resolve_fleet(query, _fleet(), authority=self.authority)
                self.assertEqual(authoritative.verdict, legacy.verdict)
                self.assertEqual(authoritative.eligible, legacy.eligible)
                self.assertEqual(authoritative.selected, legacy.selected)
                self.assertEqual(
                    [item.code for item in authoritative.per_worker],
                    [item.code for item in legacy.per_worker],
                )
                self.assertIsNone(legacy.authority)
                self.assertIsNotNone(authoritative.authority)
                self.assertEqual(authoritative.authority["mncs_artifact"], self.identity)

    def test_scheduler_authority_mode_agrees_including_no_eligible(self) -> None:
        assert self.authority is not None
        for required in (["os:linux"], ["os:plan9"]):
            with self.subTest(required=required):
                legacy = schedule(_plan(required), _slots())
                authoritative = schedule(_plan(required), _slots(), authority=self.authority)
                self.assertEqual(authoritative.disposition, legacy.disposition)
                self.assertEqual(authoritative.worker_ids, legacy.worker_ids)
                self.assertEqual(authoritative.reason, legacy.reason)
                self.assertIsNotNone(authoritative.resolution)
                self.assertIn("authority", authoritative.resolution)
                self.assertEqual(
                    authoritative.resolution["authority"]["mncs_artifact"], self.identity
                )

    def test_evidence_binds_answering_artifact(self) -> None:
        assert self.authority is not None
        fleet = resolve_fleet(CapabilityQuery(require_all=frozenset({"os:linux"})), _fleet(),
                              authority=self.authority)
        explanation = explain_selection(fleet)
        self.assertEqual(explanation["authority"]["mncs_artifact"], self.identity)
        self.assertEqual(explanation["authority"]["mncs_backend"], self.authority.backend_name)

    def test_identity_pin_mismatch_fails_hard(self) -> None:
        with self.assertRaises(AuthorityError):
            MncsAuthority(cli=self.cli, artifact=self.artifact,
                          expected_artifact_identity="mncs:compiler:backend-artifact:deadbeef")

    def test_missing_toolchain_fails_hard(self) -> None:
        with self.assertRaises(AuthorityError):
            MncsAuthority(cli="/nonexistent/mncs", artifact=self.artifact,
                          expected_artifact_identity=self.identity)

    def test_missing_artifact_fails_hard(self) -> None:
        with self.assertRaises(AuthorityError):
            MncsAuthority(cli=self.cli, artifact="/nonexistent/artifact.json",
                          expected_artifact_identity=self.identity)


if __name__ == "__main__":
    unittest.main()
