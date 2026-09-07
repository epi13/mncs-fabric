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
- the verified bytes are what executes: replacing or modifying the
  artifact file after construction cannot affect execution;
- answers correlate by case identity: duplicates, omissions, extras,
  reordering, and unknown variants fail closed (proven with a stub CLI,
  no toolchain needed);
- hand-authored ABI tables match ``mncs abi`` output mechanically;
- misconfiguration fails hard (AuthorityError), never silently back;
- worker identities are opaque: renaming a fleet changes no capability
  decision (identity is only the documented final tie-break).

Worker IDs below are deliberately meaningless (``node-7f31`` rather
than ``w-linux``): they must tell the scheduler nothing about OS,
architecture, capability, freshness, liveness, or role.

Gated tests need the toolchain (``MNCS_FABRIC_RUN_TOOLCHAIN_TESTS=1``);
stub-CLI correlation tests always run.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
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

# Opaque fleet identities: hex-suffixed node names carrying no semantic
# facts. Profiles are assigned by position, never by name.
FLEET_IDS = ("node-7f31", "worker-a92c", "node-44b1")
RENAMED_IDS = ("node-1a01", "node-9d77", "node-55e2")


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


def _profiles() -> list[dict]:
    """Three capability profiles; identity is attached separately."""
    return [
        {"capabilities": frozenset({"os:linux"}), "env": {"os": "linux", "arch": "x86_64"},
         "liveness": "AVAILABLE", "age": 5.0},
        {"capabilities": frozenset({"os:linux"}), "env": {"os": "linux", "arch": "x86_64"},
         "liveness": "AVAILABLE", "age": 9999.0},
        {"capabilities": frozenset({"os:windows"}), "env": {"os": "windows", "arch": "x86_64"},
         "liveness": "AVAILABLE", "age": 5.0},
    ]


def _fleet(ids: tuple[str, ...] = FLEET_IDS) -> list[WorkerSnapshot]:
    return [
        WorkerSnapshot(worker_id=worker_id, capabilities=profile["capabilities"],
                       env=profile["env"], liveness=profile["liveness"],
                       capability_age_seconds=profile["age"])
        for worker_id, profile in zip(ids, _profiles())
    ]


def _slots(ids: tuple[str, ...] = FLEET_IDS) -> list[WorkerSlot]:
    return [
        WorkerSlot(worker_id=worker_id, capabilities=profile["capabilities"],
                   worker_env=profile["env"], capability_age_seconds=profile["age"])
        for worker_id, profile in zip(ids, _profiles())
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


STUB_CLI = """#!/usr/bin/env python3
""" + '''"""Stub for `mncs experiment execute`, driven by STUB_SCENARIO.

Reads the batch corpus, answers candidate_resolve rows from the legacy
ordering (duplicated here only to drive failure modes), and emits
observations per scenario: ok, reorder, dup, missing-extra, extra,
unknown-variant, non-json. Any other argv shape exits nonzero.
"""
import json
import os
import sys

ORDER = ["ELIGIBLE", "CAPABILITY_UNSATISFIED", "POLICY_DENIED",
         "PROVENANCE_UNVERIFIED", "WORKER_STALE", "WORKER_UNAVAILABLE",
         "WORKER_DISCONNECTED"]
MNCS = {"ELIGIBLE": "Eligible", "CAPABILITY_UNSATISFIED": "CapabilityUnsatisfied",
        "POLICY_DENIED": "PolicyDenied", "PROVENANCE_UNVERIFIED": "ProvenanceUnverified",
        "WORKER_STALE": "WorkerStale", "WORKER_UNAVAILABLE": "WorkerUnavailable",
        "WORKER_DISCONNECTED": "WorkerDisconnected"}


def variant(code):
    name = MNCS[code]
    return {"finite": {"type_identity": "mncs:0.2:finite-type:fabric.worker_capability::ResolutionCode",
                       "variant_identity": f"mncs:0.2:finite-variant:fabric.worker_capability::ResolutionCode::{name}",
                       "discriminant": ORDER.index(code)}}


def health(args):
    live = args[0]["finite"]["variant_identity"].rsplit("::", 1)[-1]
    fresh = args[1]["finite"]["variant_identity"].rsplit("::", 1)[-1]
    ok = [args[2]["boolean"]["value"], args[3]["boolean"]["value"], args[4]["boolean"]["value"]]
    if live == "Disconnected":
        return "WORKER_DISCONNECTED"
    if live == "Unavailable":
        return "WORKER_UNAVAILABLE"
    if fresh == "Stale":
        return "WORKER_STALE"
    if not ok[1]:
        return "POLICY_DENIED"
    if not ok[0]:
        return "PROVENANCE_UNVERIFIED"
    if not ok[2]:
        return "CAPABILITY_UNSATISFIED"
    return "ELIGIBLE"


def main():
    if len(sys.argv) != 5 or sys.argv[1:3] != ["experiment", "execute"]:
        sys.stderr.write("stub: unexpected argv\\n")
        return 2
    scenario = os.environ.get("STUB_SCENARIO", "ok")
    if scenario == "non-json":
        sys.stdout.write("not json at all")
        return 0
    corpus = json.load(open(sys.argv[4]))
    cases = corpus["cases"]
    if scenario == "missing-extra":
        cases = cases[:-1]
    observations = []
    for case in cases:
        code = health(case["request"]["arguments"])
        observations.append({"case_id": case["id"], "status": "returned",
                             "returned": [variant(code)], "expected": [],
                             "expectation_met": True, "steps": 1,
                             "failure_reason": None})
    if scenario == "reorder":
        observations = observations[::-1]
    elif scenario == "dup" and len(observations) >= 2:
        observations[1] = dict(observations[0])
    elif scenario == "extra":
        observations.append(dict(observations[0], case_id="authority-999"))
    elif scenario == "unknown-variant":
        bad = dict(variant("ELIGIBLE"))
        bad["finite"] = dict(bad["finite"], variant_identity="mncs:0.2:finite-variant:fabric.worker_capability::ResolutionCode::Nope")
        observations[0] = dict(observations[0], returned=[bad])
    json.dump(observations, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


class StubCliTestBase(unittest.TestCase):
    """Fail-closed correlation proven without the toolchain."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="fabric-mncs-stub-")
        cls.stub = Path(cls._tmp.name) / "stub-mncs"
        cls.stub.write_text(STUB_CLI, encoding="utf-8")
        cls.stub.chmod(cls.stub.stat().st_mode | stat.S_IXUSR)
        artifact = {"identity": "pin-stub", "artifact_kind": "research_bytecode",
                    "backend": {"name": "stub"}}
        cls.artifact = Path(cls._tmp.name) / "artifact.json"
        cls.artifact.write_text(json.dumps(artifact), encoding="utf-8")
        cls.authority = MncsAuthority(cli=str(cls.stub), artifact=str(cls.artifact),
                                      expected_artifact_identity="pin-stub")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _rows(self, count: int = 2) -> list[ResolveInputs]:
        rows = [
            ResolveInputs(liveness="AVAILABLE", freshness="fresh",
                          provenance_ok=True, env_ok=True, intent_ok=True),
            ResolveInputs(liveness="AVAILABLE", freshness="stale",
                          provenance_ok=True, env_ok=True, intent_ok=True),
            ResolveInputs(liveness="DISCONNECTED", freshness="fresh",
                          provenance_ok=False, env_ok=False, intent_ok=False),
        ]
        return rows[:count]

    def _run(self, scenario: str, count: int = 2) -> list[str]:
        previous = os.environ.get("STUB_SCENARIO")
        os.environ["STUB_SCENARIO"] = scenario
        try:
            return self.authority.resolve_codes(self._rows(count))
        finally:
            if previous is None:
                os.environ.pop("STUB_SCENARIO", None)
            else:
                os.environ["STUB_SCENARIO"] = previous


class TestStubCorrelation(StubCliTestBase):
    def test_ok_batch_answers_in_row_order(self) -> None:
        self.assertEqual(self._run("ok", 3), ["ELIGIBLE", "WORKER_STALE", "WORKER_DISCONNECTED"])

    def test_reordered_answers_still_correlate(self) -> None:
        self.assertEqual(self._run("reorder", 3), ["ELIGIBLE", "WORKER_STALE", "WORKER_DISCONNECTED"])

    def test_duplicate_answer_fails_closed(self) -> None:
        with self.assertRaises(AuthorityError):
            self._run("dup", 2)

    def test_missing_answer_fails_closed(self) -> None:
        with self.assertRaises(AuthorityError):
            self._run("missing-extra", 2)

    def test_extra_answer_fails_closed(self) -> None:
        with self.assertRaises(AuthorityError):
            self._run("extra", 2)

    def test_unknown_variant_fails_closed(self) -> None:
        with self.assertRaises(AuthorityError):
            self._run("unknown-variant", 2)

    def test_non_json_output_fails_closed(self) -> None:
        with self.assertRaises(AuthorityError):
            self._run("non-json", 2)


class TestStubConfiguration(unittest.TestCase):
    def test_stub_wrong_pin_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fabric-mncs-stub-cfg-") as tmp:
            artifact = Path(tmp) / "artifact.json"
            artifact.write_text(json.dumps({"identity": "pin-a", "artifact_kind": "research_bytecode",
                                            "backend": {"name": "stub"}}), encoding="utf-8")
            with self.assertRaises(AuthorityError):
                MncsAuthority(cli=sys.executable, artifact=str(artifact),
                              expected_artifact_identity="pin-b")


class MncsAuthorityTestBase(unittest.TestCase):
    cli: str = ""
    artifact: str = ""
    identity: str = ""
    artifact_sha256: str = ""
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
        raw = Path(artifact).read_bytes()
        identity = str(json.loads(raw.decode("utf-8"))["identity"])
        cls.artifact = artifact
        cls.identity = identity
        cls.artifact_sha256 = hashlib.sha256(raw).hexdigest()
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
                self.assertEqual(authoritative.authority["mncs_artifact_sha256"], self.artifact_sha256)

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

    def test_rename_invariance_across_identical_fleets(self) -> None:
        # Renaming every worker changes no capability decision: codes match
        # positionally, verdicts match, and selection maps by profile
        # position (identity only breaks full ties, proven below).
        assert self.authority is not None
        queries = [
            CapabilityQuery(require_all=frozenset({"os:linux"})),
            CapabilityQuery(require_all=frozenset({"os:plan9"})),
            CapabilityQuery(require_all=frozenset(), prefer=frozenset({"os:linux"})),
        ]
        for query in queries:
            with self.subTest(query=query):
                for authority in (None, self.authority):
                    first = resolve_fleet(query, _fleet(FLEET_IDS), authority=authority)
                    second = resolve_fleet(query, _fleet(RENAMED_IDS), authority=authority)
                    self.assertEqual(first.verdict, second.verdict)
                    # per_worker sorts by worker ID, so compare by profile
                    # position rather than list order.
                    first_codes = {FLEET_IDS.index(item.worker_id): item.code
                                   for item in first.per_worker}
                    second_codes = {RENAMED_IDS.index(item.worker_id): item.code
                                    for item in second.per_worker}
                    self.assertEqual(first_codes, second_codes)
                    self.assertEqual(len(first.eligible), len(second.eligible))
                    # Selection maps by profile position through the rename.
                    first_selected = [FLEET_IDS.index(w) for w in first.selected]
                    second_selected = [RENAMED_IDS.index(w) for w in second.selected]
                    self.assertEqual(first_selected, second_selected)

    def test_identity_is_only_a_tie_breaker(self) -> None:
        # Two identical profiles: same codes, deterministic selection of
        # the lexicographically smaller opaque ID on both paths.
        assert self.authority is not None
        profile = {"capabilities": frozenset({"os:linux"}), "env": {"os": "linux", "arch": "x86_64"},
                   "liveness": "AVAILABLE", "age": 5.0}
        twins = [
            WorkerSnapshot(worker_id=worker_id, capabilities=profile["capabilities"],
                           env=profile["env"], liveness=profile["liveness"],
                           capability_age_seconds=profile["age"])
            for worker_id in ("node-b201", "node-a100")
        ]
        query = CapabilityQuery(require_all=frozenset({"os:linux"}))
        for authority in (None, self.authority):
            fleet = resolve_fleet(query, twins, authority=authority)
            self.assertEqual([item.code for item in fleet.per_worker], ["ELIGIBLE", "ELIGIBLE"])
            self.assertEqual(fleet.selected, ("node-a100",))

    def test_evidence_binds_answering_artifact(self) -> None:
        assert self.authority is not None
        self.assertEqual(self.authority.artifact_sha256, self.artifact_sha256)
        fleet = resolve_fleet(CapabilityQuery(require_all=frozenset({"os:linux"})), _fleet(),
                              authority=self.authority)
        explanation = explain_selection(fleet)
        self.assertEqual(explanation["authority"]["mncs_artifact"], self.identity)
        self.assertEqual(explanation["authority"]["mncs_artifact_sha256"], self.artifact_sha256)
        self.assertEqual(explanation["authority"]["mncs_backend"], self.authority.backend_name)

    def test_replacement_after_construction_cannot_affect_execution(self) -> None:
        # The review finding: the artifact path is replaced wholesale after
        # the authority is built. Execution must still answer from the
        # verified bytes, with evidence bound to them.
        assert self.authority is not None
        Path(self.artifact).write_text(
            json.dumps({"identity": "mncs:compiler:backend-artifact:impostor",
                        "artifact_kind": "research_bytecode", "backend": {"name": "impostor"}}),
            encoding="utf-8",
        )
        codes = self.authority.resolve_codes([
            ResolveInputs(liveness="AVAILABLE", freshness="fresh",
                          provenance_ok=True, env_ok=True, intent_ok=True),
        ])
        self.assertEqual(codes, ["ELIGIBLE"])
        self.assertEqual(self.authority.evidence()["mncs_artifact"], self.identity)
        self.assertEqual(self.authority.evidence()["mncs_artifact_sha256"], self.artifact_sha256)

    def test_inplace_modification_after_construction_cannot_affect_execution(self) -> None:
        assert self.authority is not None
        with open(self.artifact, "ab") as handle:
            handle.write(b"\n" + b"x" * 65536)
        codes = self.authority.resolve_codes([
            ResolveInputs(liveness="AVAILABLE", freshness="stale",
                          provenance_ok=True, env_ok=True, intent_ok=True),
        ])
        self.assertEqual(codes, ["WORKER_STALE"])
        self.assertEqual(self.authority.evidence()["mncs_artifact_sha256"], self.artifact_sha256)

    def test_abi_tables_match_toolchain(self) -> None:
        # Hand-authored finite encodings fail loudly on enum reorder,
        # rename, module-identity, or signature drift (issue 5).
        assert self.authority is not None
        completed = subprocess.run(
            [self.cli, "abi", str(SOURCE)],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-1000:])
        abi = json.loads(completed.stdout)
        functions = abi.get("functions", {})
        self.assertIn("candidate_resolve", functions)
        entry = functions["candidate_resolve"]
        inputs = entry.get("inputs", [])
        self.assertEqual(len(inputs), 5)
        from mncs_fabric.mncs_authority import FRESHNESS_MNCS, LIVENESS_MNCS

        for position, (mncs_name, table) in enumerate(
            (("Liveness", LIVENESS_MNCS), ("Freshness", FRESHNESS_MNCS))
        ):
            finite = inputs[position]["finite"]
            self.assertEqual(
                finite["type_identity"], f"mncs:0.2:finite-type:fabric.worker_capability::{mncs_name}")
            for key, variant in table.items():
                discriminant = list(table).index(key)
                self.assertEqual(
                    finite["variants"][str(discriminant)],
                    f"mncs:0.2:finite-variant:fabric.worker_capability::{mncs_name}::{variant}")
        for position in (2, 3, 4):
            self.assertEqual(inputs[position], {"scalar": {"semantic_type": "bool"}})
        outputs = entry.get("outputs", [])
        self.assertEqual(len(outputs), 1)
        variants = outputs[0]["finite"]["variants"]
        self.assertEqual(
            outputs[0]["finite"]["type_identity"],
            "mncs:0.2:finite-type:fabric.worker_capability::ResolutionCode")
        from mncs_fabric.mncs_authority import CODE_PY

        self.assertEqual(
            {discriminant: name for discriminant, name in
             ((int(index), identity.rsplit("::", 1)[-1]) for index, identity in variants.items())},
            {index: name for index, name in enumerate(CODE_PY)},
        )

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
