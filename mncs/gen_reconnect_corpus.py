#!/usr/bin/env python3
"""Generate the execution corpus for mncs/fabric_reconnect.mncs.

Reads the Python reconnect classifier (the current runtime authority in
`src/mncs_fabric/update_lifecycle.py::observe_reconnect`) over real
transactions and emits every evidence shape as an MNCS ExecutionCorpus.
`mncs experiment run` executes the compiled module;
`tests/test_mncs_reconnect_policy.py` asserts the execution agrees with
Python on every case.

Caller reductions (documented in the MNCS module): identity text folds to
`same_identity`, version/artifact comparison folds to `version_matched`,
parse failure folds to `version_malformed`, and the recovery precondition
folds to `present_at_expected`. The corpus builds real evidence, applies
the same reductions, and pins both MNCS entrypoints against Python.

Run from the repository root: python3 mncs/gen_reconnect_corpus.py
"""

import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.update_lifecycle import (  # noqa: E402
    build_update_transaction,
    observe_reconnect,
    version_matches_expected,
)
from mncs_fabric.versioning import parse_fabric_version  # noqa: E402

MODULE = "fabric.reconnect"

STATE_MNCS = {
    "DISCONNECT_EXPECTED": "DisconnectExpected",
    "RECONNECTING": "Reconnecting",
    "VERSION_VERIFYING": "VersionVerifying",
}
STATE_INDEX = {"DisconnectExpected": 0, "Reconnecting": 1, "VersionVerifying": 2, "Other": 3}
OTHER_STATES = ["READY", "FAILED", "CERTIFYING"]

OBS_MNCS = {
    "AWAITING_DISCONNECT": "AwaitingDisconnect",
    "EXPECTED_DISCONNECT": "ExpectedDisconnect",
    "AWAITING_RECONNECT": "AwaitingReconnect",
    "RECONNECTED": "Reconnected",
    "DEADLINE_EXPIRED": "DeadlineExpired",
    "WRONG_IDENTITY": "WrongIdentity",
    "WRONG_VERSION": "WrongVersion",
    "STILL_CONNECTED": "StillConnected",
    "MALFORMED_VERSION": "MalformedVersion",
}
OBS_INDEX = {name: index for index, name in enumerate(
    ["AwaitingDisconnect", "ExpectedDisconnect", "AwaitingReconnect", "Reconnected",
     "DeadlineExpired", "WrongIdentity", "WrongVersion", "StillConnected", "MalformedVersion"]
)}

NEXT_MNCS = {
    "DISCONNECT_EXPECTED": "DisconnectExpected",
    "RECONNECTING": "Reconnecting",
    "VERSION_VERIFYING": "VersionVerifying",
    "CERTIFYING": "Certifying",
    "ROLLBACK_APPLYING": "RollbackApplying",
    "FAILED": "Failed",
    "QUARANTINED": "Quarantined",
}
NEXT_INDEX = {name: index for index, name in enumerate(
    ["DisconnectExpected", "Reconnecting", "VersionVerifying", "Certifying",
     "RollbackApplying", "Failed", "Quarantined", "Other"]
)}

EXPECTED_VERSION = "0.2.0a31"
MATCH_VERSION = "0.2.0a31"
MISMATCH_VERSION = "0.2.0a30"
MALFORMED_VERSION_TEXT = "banana"
EXPECTED_ARTIFACT = "sha256:" + "ab" * 32
OTHER_ARTIFACT = "sha256:" + "cd" * 32
DEADLINE = "2030-01-01T00:00:00Z"
NOW_FRESH = "2029-06-01T00:00:00Z"
NOW_EXPIRED = "2031-06-01T00:00:00Z"
WORKER = "worker-alpha"


def finite(module, type_name, variant_name, discriminant):
    return {
        "finite": {
            "type_identity": f"mncs:0.2:finite-type:{module}::{type_name}",
            "variant_identity": (
                f"mncs:0.2:finite-variant:{module}::{type_name}::{variant_name}"
            ),
            "discriminant": discriminant,
        }
    }


def boolean(value):
    return {"boolean": {"value": bool(value)}}


def case(case_id, function, arguments, expected, step_budget=4096):
    return {
        "id": case_id,
        "request": {
            "schema_version": "0.1",
            "target": {"module": MODULE, "function": function},
            "arguments": list(arguments),
            "step_budget": step_budget,
        },
        "expected": [expected],
    }


def make_transaction(state):
    return build_update_transaction(
        worker_id=WORKER,
        state=state,
        expected_version=EXPECTED_VERSION,
        previous_version="0.2.0a30",
        artifact_identity=EXPECTED_ARTIFACT,
        previous_artifact_identity=None,
        deadline=DEADLINE,
        reason="conversion corpus",
    )


def main():
    scenarios = []

    def add(name, **evidence):
        scenarios.append((name, evidence))

    for expired, connected, seen in itertools.product((False, True), repeat=3):
        for recovery in (False, True):
            presents = (False, True) if recovery else (False,)
            for present in presents:
                now = NOW_EXPIRED if expired else NOW_FRESH
                for state in ("DISCONNECT_EXPECTED", "RECONNECTING"):
                    tag = f"{state}-exp{int(expired)}-conn{int(connected)}-seen{int(seen)}-rec{int(recovery)}-present{int(present)}"
                    observed_version = MATCH_VERSION if present else MISMATCH_VERSION
                    add(
                        tag,
                        state=state,
                        expired=expired,
                        connected=connected,
                        seen_disconnect=seen,
                        observed_worker_id=WORKER if (present or connected) else None,
                        observed_version=observed_version if connected else None,
                        observed_artifact_identity=EXPECTED_ARTIFACT if (present and connected) else None,
                        now=now,
                        recovery=recovery,
                    )
    # Identity mismatch inside RECONNECTING.
    for expired in (False, True):
        add(
            f"RECONNECTING-exp{int(expired)}-wrongid",
            state="RECONNECTING",
            expired=expired,
            connected=True,
            seen_disconnect=True,
            observed_worker_id="worker-beta",
            observed_version=MATCH_VERSION,
            observed_artifact_identity=None,
            now=NOW_EXPIRED if expired else NOW_FRESH,
            recovery=False,
        )
    # VERSION_VERIFYING: identity x version x artifact x recovery shapes.
    for same in ("none", "match", "mismatch"):
        observed_id = {"none": None, "match": WORKER, "mismatch": "worker-beta"}[same]
        for version in ("none", "match", "mismatch", "malformed"):
            observed_version = {
                "none": None, "match": MATCH_VERSION,
                "mismatch": MISMATCH_VERSION, "malformed": MALFORMED_VERSION_TEXT,
            }[version]
            for artifact in ("none", "match", "mismatch"):
                observed_artifact = {
                    "none": None, "match": EXPECTED_ARTIFACT, "mismatch": OTHER_ARTIFACT,
                }[artifact]
                for recovery in (False, True):
                    presents = (False, True) if recovery else (False,)
                    for present in presents:
                        add(
                            f"VERSION_VERIFYING-id{same}-ver{version}-art{artifact}-rec{int(recovery)}-present{int(present)}",
                            state="VERSION_VERIFYING",
                            expired=False,
                            connected=True,
                            seen_disconnect=True,
                            observed_worker_id=observed_id,
                            observed_version=observed_version,
                            observed_artifact_identity=observed_artifact,
                            now=NOW_FRESH,
                            recovery=recovery,
                        )
    # States where reconnect observation is not applicable.
    for state in OTHER_STATES:
        for connected in (False, True):
            add(
                f"{state}-conn{int(connected)}",
                state=state,
                expired=False,
                connected=connected,
                seen_disconnect=False,
                observed_worker_id=None,
                observed_version=None,
                observed_artifact_identity=None,
                now=NOW_FRESH,
                recovery=False,
            )

    cases = []
    for name, evidence in scenarios:
        state = evidence.pop("state")
        expired_flag = evidence.pop("expired")
        transaction = make_transaction(state)
        result = observe_reconnect(transaction, **evidence)
        observed_id = evidence["observed_worker_id"]
        observed_version = evidence["observed_version"]
        observed_artifact = evidence["observed_artifact_identity"]
        same_identity = observed_id in (None, WORKER)
        version_malformed = (
            observed_version is not None and parse_fabric_version(observed_version) is None
        )
        version_ok = version_matches_expected(observed_version, EXPECTED_VERSION)
        artifact_clash = bool(
            EXPECTED_ARTIFACT and observed_artifact
            and observed_artifact != EXPECTED_ARTIFACT
        )
        version_matched = bool(version_ok and not artifact_clash)
        present_at_expected = bool(
            evidence["connected"] and same_identity
            and version_matches_expected(observed_version, EXPECTED_VERSION)
        )
        state_mncs = STATE_MNCS.get(state, "Other")
        args = [
            finite(MODULE, "ReconnectState", state_mncs, STATE_INDEX[state_mncs]),
            boolean(expired_flag),
            boolean(evidence["connected"]),
            boolean(evidence["seen_disconnect"]),
            boolean(same_identity),
            boolean(version_matched),
            boolean(version_malformed),
            boolean(evidence["recovery"]),
            boolean(present_at_expected),
        ]
        obs_mncs = OBS_MNCS[result["observation"]]
        next_raw = result["next_state"]
        # The MNCS module observes only the four-class ReconnectState, so an
        # input outside DISCONNECT_EXPECTED/RECONNECTING/VERSION_VERIFYING
        # always yields NextState.Other even though Python echoes the full
        # input state back. The reduction is pinned here, not hidden.
        if state in STATE_MNCS:
            next_mncs = NEXT_MNCS.get(next_raw, "Other")
        else:
            assert next_raw == state, (next_raw, state)
            next_mncs = "Other"
        cases.append(
            case(
                f"obs-{name}", "candidate_observation", args,
                finite(MODULE, "Observation", obs_mncs, OBS_INDEX[obs_mncs]),
            )
        )
        cases.append(
            case(
                f"next-{name}", "candidate_next", args,
                finite(MODULE, "NextState", next_mncs, NEXT_INDEX[next_mncs]),
            )
        )
    document = {
        "schema_version": "0.1",
        "name": "fabric-reconnect-exhaustive",
        "cases": cases,
    }
    out = os.path.join(HERE, "fabric_reconnect_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases over {len(scenarios)} scenarios")


if __name__ == "__main__":
    main()
