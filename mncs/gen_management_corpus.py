#!/usr/bin/env python3
"""Generate the exhaustive execution corpus for mncs/fabric_management.mncs.

Reads the Python management-state tables (the current runtime authority)
and emits every state pair plus scheduling/invariant arms as an MNCS
ExecutionCorpus. `mncs experiment run` executes the compiled module;
`tests/test_mncs_management_policy.py` asserts the execution agrees with
Python on every case.

Run from the repository root: python3 mncs/gen_management_corpus.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from mncs_fabric.management import (  # noqa: E402
    _TRANSITIONS,
    management_allows_work,
)

MODULE = "fabric.management"
STATES = ["READY", "BUSY", "DRAINING", "MAINTENANCE", "VERIFYING", "DEGRADED", "QUARANTINED"]
VERDICTS = ["ALLOWED", "DENIED"]


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


def main():
    cases = []
    for source in STATES:
        for target in STATES:
            # Strict table: the MNCS module owns the table without the
            # host-side reflexive closure in `can_transition`.
            allowed = target in _TRANSITIONS[source]
            verdict = "ALLOWED" if allowed else "DENIED"
            cases.append(
                case(
                    f"transition-{source}-{target}",
                    "candidate",
                    [
                        finite(MODULE, "MgmtState", source, STATES.index(source)),
                        finite(MODULE, "MgmtState", target, STATES.index(target)),
                    ],
                    finite(MODULE, "TransitionVerdict", verdict, VERDICTS.index(verdict)),
                )
            )
    for state in STATES:
        cases.append(
            case(
                f"allows-work-{state}",
                "candidate_allows_work",
                [finite(MODULE, "MgmtState", state, STATES.index(state))],
                boolean(management_allows_work(state)),
            )
        )
    for state in STATES:
        for failed in (False, True):
            # Python authority: READY with FAILED certification is rejected
            # in build_management_state; every other combination is allowed.
            expected = not (state == "READY" and failed)
            cases.append(
                case(
                    f"certification-{state}-failed-{int(failed)}",
                    "candidate_certification",
                    [
                        finite(MODULE, "MgmtState", state, STATES.index(state)),
                        boolean(failed),
                    ],
                    boolean(expected),
                )
            )
    document = {
        "schema_version": "0.1",
        "name": "fabric-management-exhaustive",
        "cases": cases,
    }
    out = os.path.join(HERE, "fabric_management_corpus.json")
    with open(out, "w") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main()
